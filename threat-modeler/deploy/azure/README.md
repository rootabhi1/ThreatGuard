# Deploying Threat Modeler to Azure App Service

Three ways to deploy, in increasing order of complexity. **All produce the same result** — a Web App for Containers running on Linux App Service Plan B1, with HTTPS enforced and ACR pull via managed identity.

| Path | When to use |
|---|---|
| `deploy.sh` | One-shot, opinionated, fastest. Run it once, you have a URL. |
| `main.bicep` | You want infra-as-code so you can tear down + redeploy cleanly. |
| GitHub Actions | You want every push to `main` to redeploy automatically. |

---

## Prerequisites (all paths)

```bash
az login
az account set --subscription "<your-subscription-name-or-id>"
```

You also need:
- **Subscription roles:** Contributor on the subscription, or Owner on the resource group you'll deploy into (because we create a role assignment for ACR pull).
- **Resource provider registration:** App Service and ACR providers should already be registered. If not: `az provider register --namespace Microsoft.Web --wait` and same for `Microsoft.ContainerRegistry`.

---

## Path 1 — `deploy.sh` (recommended for first deploy)

From the project root:

```bash
# Optional: customize via env vars
export ANTHROPIC_API_KEY="sk-ant-..."   # leave unset to disable LLM enrichment
export LOCATION="eastus"
export RG="threat-modeler-rg"
export PLAN_SKU="B1"

./deploy/azure/deploy.sh
```

Takes 5–8 minutes. Last line of output is your HTTPS URL.

The script is idempotent — re-running it updates the image and config in place rather than failing on existing resources.

### What it creates

```
threat-modeler-rg/
├── tmacrXXXXXX           ACR (Basic SKU, ~$5/mo)
├── threat-modeler-plan   App Service Plan B1 Linux (~$13/mo)
└── threat-modeler-XXX    Web App for Containers
```

### After it finishes

Tail the logs (helpful while the container starts up the first time):
```bash
az webapp log tail -n threat-modeler-XXX -g threat-modeler-rg
```

The first request after deploy is slow — App Service has to pull the image from ACR (~200 MB) and start the container. Expect 60–120 seconds of cold start.

### Add ANTHROPIC_API_KEY later

```bash
az webapp config appsettings set \
  -n threat-modeler-XXX -g threat-modeler-rg \
  --settings ANTHROPIC_API_KEY="sk-ant-..."
```

The app picks it up after the next restart (which the command triggers automatically).

---

## Path 2 — Bicep template

```bash
# 1. Create the RG and ACR first (Bicep needs ACR to exist before it can build into it)
az group create -n threat-modeler-rg -l eastus
az acr create -n tmacrXXXXXX -g threat-modeler-rg --sku Basic

# 2. Build the image
az acr build -t threat-modeler:v1 -r tmacrXXXXXX -f Dockerfile .

# 3. Deploy with Bicep
az deployment group create \
  -g threat-modeler-rg \
  -f deploy/azure/main.bicep \
  -p appName=threat-modeler-prod \
     acrName=tmacrXXXXXX \
     imageTag=v1 \
     anthropicApiKey="sk-ant-..."

# 4. Get the URL
az deployment group show \
  -g threat-modeler-rg -n main \
  --query properties.outputs.appUrl.value -o tsv
```

To tear it all down: `az group delete -n threat-modeler-rg --yes --no-wait`.

---

## Path 3 — GitHub Actions auto-deploy

After your first deploy via path 1 or 2, set up CI:

1. Edit `.github/workflows/deploy-azure.yml` and update the three env values at the top (`AZURE_WEBAPP_NAME`, `ACR_NAME`, and `AZURE_RESOURCE_GROUP` if you customized it).

2. Set up OIDC federation as described at the bottom of that workflow file. This is a one-time ~5-minute setup that lets GitHub Actions authenticate to Azure without storing a service-principal password as a secret.

3. Push to `main`. The workflow builds via ACR Tasks, swaps the Web App image, restarts, and runs a smoke test against `/api/health`.

---

## Custom domain + HTTPS

See [`custom-domain.md`](./custom-domain.md). TL;DR: add a CNAME + TXT record at your registrar, run two `az` commands, you have a free Microsoft-managed cert.

---

## What this deployment does *not* include

By design, to keep things simple. If any of these matter:

- **No persistence.** SQLite-saved projects vanish on restart. If that bothers you, mount Azure Files (~10 lines of az CLI) or migrate to Azure Database for PostgreSQL.
- **No authentication.** Anyone with the URL can run analyses. Easiest fix: enable App Service's built-in Easy Auth with Microsoft Entra ID:
  ```bash
  az webapp auth update -n <app-name> -g <rg> \
    --enabled true --action RedirectToLoginPage --redirect-provider AzureActiveDirectory
  ```
  Then bind your tenant under Authentication in the portal. Takes 5 minutes.
- **No private networking.** The app is publicly accessible (over HTTPS only). For VNet-only access, you'd swap to App Service Environment v3 (~$1k/mo, overkill) or front it with an Application Gateway with a private endpoint on the App Service.
- **No CDN / edge caching.** Static assets are tiny and served directly. If you really need it, Azure Front Door in front works fine.

---

## Costs (rough)

| Resource | SKU | $/mo |
|---|---|---|
| App Service Plan | B1 Linux | ~$13 |
| Azure Container Registry | Basic | ~$5 |
| Outbound bandwidth | first 100 GB/mo | free |
| Managed certificate | — | free |
| **Total** | | **~$18/mo** |

If you go to P1V3 for production (auto-scale, deployment slots, better cold-start): ~$73/mo for the plan, total ~$78/mo.

If you set `ANTHROPIC_API_KEY`, you also pay per-token to Anthropic on the LLM enrichment path — roughly $0.001 per threat enriched at current Haiku 4.5 prices. A 100-threat analysis costs about $0.10.

---

## Troubleshooting

**App returns 502 / "Application Error" for the first 2 minutes after deploy.**
Normal. The container is starting. `az webapp log tail` to watch progress.

**App still returns 502 after 5+ minutes.**
Image likely failed to pull or start. Check:
```bash
az webapp log tail -n <app> -g <rg>
az webapp log show -n <app> -g <rg>
```
Common causes: managed identity hasn't propagated AcrPull yet (wait 60s and restart), or the image entrypoint crashed (check stderr in logs).

**`az acr build` fails with "registry not found".**
ACR names must be globally unique. Either pick a different name or check that the registry exists in the right subscription.

**HTTPS works on `*.azurewebsites.net` but custom domain serves the wrong cert.**
You added the hostname but didn't bind the cert. Run `az webapp config ssl bind` from the custom-domain doc.

**Container starts then exits.**
Almost always: the app is binding to `127.0.0.1` instead of `0.0.0.0`. We've already fixed this in the Dockerfile (`ENV HOST=0.0.0.0`) — check that env var is set in the deployed app:
```bash
az webapp config appsettings list -n <app> -g <rg> --query "[?name=='HOST']"
```

**LLM enrichment isn't working.**
Check the API key is set and the network egress isn't blocked:
```bash
az webapp config appsettings list -n <app> -g <rg> --query "[?name=='ANTHROPIC_API_KEY'].value | [0]"
```
The value is masked in the output but you can confirm it's present. Then check the logs for `[detail-llm]` lines on the next analysis run.
