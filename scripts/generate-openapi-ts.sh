#!/usr/bin/env bash
# Emit OpenAPI JSON from the FastAPI app and generate TypeScript types (openapi-typescript).
# Requires: Node.js (for npx), Python venv with app dependencies.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p openapi/ts
PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="python3"
fi
"$PY" -c "import json; from app.main import app; print(json.dumps(app.openapi()))" > openapi/openapi.json
npx --yes openapi-typescript openapi/openapi.json -o openapi/ts/schema.d.ts
echo "Wrote openapi/openapi.json and openapi/ts/schema.d.ts"
