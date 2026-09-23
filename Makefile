.PHONY: install bootstrap deploy run run-oauth run-mcp canary check-deployed ui clean

PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e .

# Provision the Google Cloud project. Run once.
bootstrap:
	./deploy/bootstrap.sh

# Deploys two services -- the public OAuth proxy and the PRIVATE control plane
# -- and each twice on first creation, because Cloud Run only reveals a URL
# after the service exists and both have to advertise their own.
deploy:
	./deploy/deploy.sh

# Local control plane against in-memory stores.
#
# P2M_ALLOW_UNAUTHENTICATED=1 turns off the ID-token check. It is the only way
# to run locally -- Google will not sign a token audienced to localhost -- and
# it must never be set on a deployed service. It logs a WARNING at startup.
run:
	P2M_USE_MEMORY_STORE=1 \
	P2M_ALLOW_UNAUTHENTICATED=1 \
	P2M_PROJECT_ID=$${PROJECT_ID:-$$(gcloud config get-value project)} \
	P2M_PUBLIC_BASE_URL=$${PUBLIC_URL:-http://localhost:8080} \
	P2M_OAUTH_BASE_URL=$${OAUTH_URL:-http://localhost:8081} \
	PYTHONPATH=src $(PYTHON) -m prompt_to_mcp.main

# The OAuth proxy, which is a separate service in deployment too.
run-oauth:
	P2M_USE_MEMORY_STORE=1 \
	PORT=$${PORT:-8081} \
	P2M_PROJECT_ID=$${PROJECT_ID:-$$(gcloud config get-value project)} \
	P2M_OAUTH_BASE_URL=$${OAUTH_URL:-http://localhost:8081} \
	PYTHONPATH=src $(PYTHON) -m prompt_to_mcp.oauth_app

# Run a generated MCP locally against a manifest file.
run-mcp:
	P2M_MANIFEST_FILE=$${MANIFEST:-./manifest.json} \
	$(PYTHON) runtime/server.py

# The deployed control plane is private, so reach the UI through a local proxy
# that attaches your identity token. Then open http://localhost:8080/ui/
ui:
	gcloud run services proxy $${SERVICE:-prompt-to-mcp} \
	  --region $${REGION:-us-central1} --project $${PROJECT_ID:-$$(gcloud config get-value project)}

canary:
	curl -fsS -H "Authorization: Bearer $$(gcloud auth print-identity-token \
	  --audiences=$${P2M_URL:?set P2M_URL})" \
	  $${P2M_URL}/v1/canary | $(PYTHON) -m json.tool

# Is the deployed service built from this tree? Mints its own identity token.
check-deployed:
	PYTHONPATH=src $(PYTHON) -m prompt_to_mcp.build_info --check $${P2M_URL:?set P2M_URL}

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf build *.egg-info src/*.egg-info
