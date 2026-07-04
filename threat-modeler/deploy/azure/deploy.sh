#!/usr/bin/env bash
# ============================================================================
#  Deploy Threat Modeler to Azure App Service for Containers
#
#  What this script does:
#    1. Creates a resource group
#    2. Creates an Azure Container Registry (ACR)
#    3. Builds and pushes the Docker image using ACR Tasks (no local Docker needed)
#    4. Creates an App Service Plan (Linux)
#    5. Creates a Web App for Containers and points it at the image
#    6. Configures app settings (port, ANTHROPIC_API_KEY if provided)
#    7. Enables HTTPS-only and managed-identity ACR pull
#    8. Prints the URL
#
#  Requirements:
#    - az CLI logged in:                  az login
#    - Right subscription selected:       az account set -s <SUB_ID>
#
#  Usage:
#    ./deploy.sh
#
#  Customize via environment variables before running, or edit the defaults below.
# ============================================================================
set -euo pipefail

# ---- Configuration (override via env vars) --------------------------------
LOCATION="${LOCATION:-eastus}"
RG="${RG:-threat-modeler-rg}"
# ACR name must be globally unique, lowercase, 5-50 alphanumeric chars.
# We append a short hash so re-runs don't collide.
ACR_NAME="${ACR_NAME:-tmacr$(echo -n "$RG-$LOCATION" | shasum | cut -c1-6)}"
PLAN_NAME="${PLAN_NAME:-threat-modeler-plan}"
PLAN_SKU="${PLAN_SKU:-B1}"            # B1 = ~$13/mo. Use P1V3 for production.
APP_NAME="${APP_NAME:-threat-modeler-$(echo -n "$RG-$LOCATION" | shasum | cut -c1-6)}"
IMAGE_NAME="${IMAGE_NAME:-threat-modeler}"
IMAGE_TAG="${IMAGE_TAG:-v1}"
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"   # Optional. Empty disables LLM enrichment.

# ---- Pretty-print helpers --------------------------------------------------
b() { printf "\n\033[1;36m▶ %s\033[0m\n" "$*"; }
ok() { printf "  \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*"; }

# Project root = parent of this script's parent directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )"

b "Threat Modeler — Azure deploy"
echo "  Resource group: $RG"
echo "  Location:       $LOCATION"
echo "  ACR:            $ACR_NAME"
echo "  App Service:    $APP_NAME"
echo "  Plan SKU:       $PLAN_SKU"
echo "  Project root:   $PROJECT_DIR"
echo "  LLM enabled:    $([[ -n "$ANTHROPIC_API_KEY" ]] && echo yes || echo no)"

# ---- 1. Resource group -----------------------------------------------------
b "1/7  Creating resource group"
az group create -n "$RG" -l "$LOCATION" --output none
ok "Resource group ready"

# ---- 2. Container registry -------------------------------------------------
b "2/7  Creating Azure Container Registry"
if az acr show -n "$ACR_NAME" -g "$RG" --output none 2>/dev/null; then
  ok "ACR $ACR_NAME already exists"
else
  az acr create -n "$ACR_NAME" -g "$RG" --sku Basic --admin-enabled false --output none
  ok "ACR created"
fi
ACR_LOGIN_SERVER="$(az acr show -n "$ACR_NAME" -g "$RG" --query loginServer -o tsv)"
echo "    Login server: $ACR_LOGIN_SERVER"

# ---- 3. Build and push image (using ACR Tasks - no local Docker required) -
b "3/7  Building image with ACR Tasks (this takes ~2-3 min)"
az acr build \
  -t "$IMAGE_NAME:$IMAGE_TAG" \
  -t "$IMAGE_NAME:latest" \
  -r "$ACR_NAME" \
  -f "$PROJECT_DIR/Dockerfile" \
  "$PROJECT_DIR" \
  --output none
ok "Image built and pushed to $ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG"

# ---- 4. App Service Plan ---------------------------------------------------
b "4/7  Creating App Service plan"
if az appservice plan show -n "$PLAN_NAME" -g "$RG" --output none 2>/dev/null; then
  ok "Plan $PLAN_NAME already exists"
else
  az appservice plan create \
    -n "$PLAN_NAME" -g "$RG" \
    --is-linux --sku "$PLAN_SKU" \
    --output none
  ok "Plan created (SKU: $PLAN_SKU)"
fi

# ---- 5. Web App ------------------------------------------------------------
b "5/7  Creating Web App"
if az webapp show -n "$APP_NAME" -g "$RG" --output none 2>/dev/null; then
  ok "Web App $APP_NAME already exists, will update its image"
  az webapp config container set \
    -n "$APP_NAME" -g "$RG" \
    --container-image-name "$ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG" \
    --container-registry-url "https://$ACR_LOGIN_SERVER" \
    --output none
else
  az webapp create \
    -n "$APP_NAME" -g "$RG" -p "$PLAN_NAME" \
    --container-image-name "$ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG" \
    --output none
  ok "Web App created"
fi

# ---- 6. Wire ACR pull via managed identity (no admin password) ------------
b "6/7  Configuring ACR pull with managed identity"
az webapp identity assign -n "$APP_NAME" -g "$RG" --output none
PRINCIPAL_ID="$(az webapp identity show -n "$APP_NAME" -g "$RG" --query principalId -o tsv)"
ACR_ID="$(az acr show -n "$ACR_NAME" -g "$RG" --query id -o tsv)"
# Idempotent — no-op if assignment already exists
az role assignment create \
  --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "AcrPull" \
  --scope "$ACR_ID" \
  --output none 2>/dev/null || true
# Tell the webapp to use the managed identity to pull from ACR
az resource update \
  --ids "$(az webapp show -n "$APP_NAME" -g "$RG" --query id -o tsv)/config/web" \
  --set properties.acrUseManagedIdentityCreds=true \
  --output none
ok "ACR pull permissions granted via managed identity"

# ---- 7. App settings + HTTPS-only ----------------------------------------
b "7/7  Configuring app settings and HTTPS"
SETTINGS=(
  "WEBSITES_PORT=8000"
  "PORT=8000"
  "HOST=0.0.0.0"
  "WEBSITES_CONTAINER_START_TIME_LIMIT=600"   # Allow up to 10 min for first cold start
  "DOCKER_REGISTRY_SERVER_URL=https://$ACR_LOGIN_SERVER"
)
if [[ -n "$ANTHROPIC_API_KEY" ]]; then
  SETTINGS+=("ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY")
  ok "ANTHROPIC_API_KEY will be set"
else
  warn "ANTHROPIC_API_KEY not provided — LLM enrichment will be disabled. Set it later with:"
  warn "  az webapp config appsettings set -n $APP_NAME -g $RG --settings ANTHROPIC_API_KEY=sk-ant-..."
fi
az webapp config appsettings set \
  -n "$APP_NAME" -g "$RG" \
  --settings "${SETTINGS[@]}" \
  --output none

# Enforce HTTPS
az webapp update -n "$APP_NAME" -g "$RG" --https-only true --output none
ok "HTTPS-only enforced"

# Restart so all settings take effect
az webapp restart -n "$APP_NAME" -g "$RG" --output none

URL="https://$(az webapp show -n "$APP_NAME" -g "$RG" --query defaultHostName -o tsv)"
echo
b "✅  Deployment complete"
echo "  URL:  $URL"
echo
echo "Logs (live tail):"
echo "  az webapp log tail -n $APP_NAME -g $RG"
echo
echo "Cold-start note: first request after deploy may take 60-120s while the container starts."
echo
echo "Custom domain setup:"
echo "  See deploy/azure/custom-domain.md"
