# Custom domain + HTTPS

App Service gives you `https://<app-name>.azurewebsites.net` for free with a wildcard
Microsoft cert. This doc covers binding **your own domain** (e.g. `threats.example.com`)
with a free Azure-managed certificate.

## What you need

- A registered domain you control (Namecheap, GoDaddy, Cloudflare, Route 53, anywhere)
- Access to your domain's DNS records
- The Threat Modeler already deployed via `deploy.sh`
- App Service Plan on **B1 or higher** (free tier doesn't support custom domains)

## TL;DR

```bash
APP_NAME="threat-modeler-xxxxxx"   # your value
RG="threat-modeler-rg"
DOMAIN="threats.example.com"       # subdomain you want

# 1. Add DNS records at your registrar (see below)
# 2. Verify and bind the hostname:
az webapp config hostname add \
  --webapp-name "$APP_NAME" -g "$RG" --hostname "$DOMAIN"

# 3. Create a managed certificate (free):
az webapp config ssl create \
  --resource-group "$RG" --name "$APP_NAME" --hostname "$DOMAIN"

# 4. Bind it (use the thumbprint from step 3 output):
THUMBPRINT="$(az webapp config ssl list -g "$RG" --query "[?subjectName=='$DOMAIN'].thumbprint | [0]" -o tsv)"
az webapp config ssl bind \
  --certificate-thumbprint "$THUMBPRINT" \
  --ssl-type SNI \
  --name "$APP_NAME" -g "$RG"
```

## DNS records to add

App Service requires **two records** for verification + routing.

For a **subdomain** like `threats.example.com`:

| Type    | Host / Name           | Value                                              |
|---------|------------------------|---------------------------------------------------|
| `CNAME` | `threats`              | `<app-name>.azurewebsites.net`                    |
| `TXT`   | `asuid.threats`        | (the verification ID — see below)                 |

For the **apex / root** like `example.com`:

| Type    | Host / Name           | Value                                              |
|---------|------------------------|---------------------------------------------------|
| `A`     | `@`                    | (App Service inbound IP — see below)              |
| `TXT`   | `asuid`                | (the verification ID — see below)                 |

Get both values with:

```bash
az webapp show -n "$APP_NAME" -g "$RG" \
  --query "{ip:inboundIpAddress, verificationId:customDomainVerificationId}" -o table
```

Wait 5–10 minutes after adding records, then run the `hostname add` command. If it
errors saying the record isn't found, give DNS another few minutes.

## When the managed certificate doesn't work

Free managed certs don't support every scenario. They **don't work** for:

- Wildcard hostnames (`*.example.com`)
- Apex domains pointed via `A` record (in some regions; CNAME flattening is fine)
- Hostnames behind Cloudflare with the orange cloud on (turn it off, or use Cloudflare's own cert)

In those cases either bring your own cert (`az webapp config ssl upload --certificate-file ... --certificate-password ...`) or use Azure Front Door in front.

## Verifying it worked

```bash
curl -I "https://$DOMAIN"
# Should return: HTTP/2 200, server: Microsoft-IIS/...
# Cert chain should show "Microsoft Azure TLS Issuing CA" via openssl s_client
```

The first browser request might take 30 seconds (cold start + SNI handshake on a fresh cert).
