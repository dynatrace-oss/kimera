#!/usr/bin/env bash
# Generates .github/Dynatrace.md from the committed template and local config.
#
# Usage:
#   bash scripts/setup-dynatrace-md.sh
#
# Prerequisites:
#   - Create .github/.dynatrace-env with your DT environment details (see .github/.dynatrace-env.example)
#   - envsubst must be available (part of gettext; install via: brew install gettext)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.github/.dynatrace-env"
TEMPLATE="${REPO_ROOT}/.github/Dynatrace.md.template"
OUTPUT="${REPO_ROOT}/.github/Dynatrace.md"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Error: ${ENV_FILE} not found."
    echo "Create it with the following contents:"
    echo ""
    echo "  DT_ENVIRONMENT=https://<your-tenant>.dev.apps.dynatracelabs.com"
    echo "  CLUSTER_NAME=<your-cluster-name>"
    echo ""
    echo "See .github/.dynatrace-env.example for a template."
    exit 1
fi

if ! command -v envsubst &>/dev/null; then
    echo "Error: envsubst not found. Install via: brew install gettext"
    exit 1
fi

# shellcheck source=/dev/null
source "${ENV_FILE}"
export DT_ENVIRONMENT CLUSTER_NAME

envsubst < "${TEMPLATE}" > "${OUTPUT}"
echo "Generated ${OUTPUT}"
echo "  DT_ENVIRONMENT=${DT_ENVIRONMENT}"
echo "  CLUSTER_NAME=${CLUSTER_NAME}"
