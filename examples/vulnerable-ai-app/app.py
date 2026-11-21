"""
Vulnerable AI Sandbox Application
Educational reference app demonstrating OWASP LLM and API9 vulnerabilities:
1. Shadow / Zombie Endpoint (/api/v1/chat without auth or guardrails)
2. Vector IDOR / Unscoped Multi-Tenant Retrieval (/api/v2/search)
3. Insecure Output Sink (/api/v2/render-summary)
"""

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any

app = FastAPI(title="Damn Vulnerable AI Service", version="2.0.0")

# Simulated in-memory vector database with multi-tenant data
MOCK_VECTOR_STORE = [
    {"id": "doc_1", "tenant_id": "tenant_alpha", "text": "Alpha Q3 revenue was $4.2M.", "secret": "ALPHA_KEY_9921"},
    {"id": "doc_2", "tenant_id": "tenant_alpha", "text": "Alpha roadmaps confidential microservice architecture."},
    {"id": "doc_3", "tenant_id": "tenant_beta", "text": "Beta secret merger terms with MegaCorp.", "secret": "BETA_SECRET_TOKEN_441"},
]

class ChatRequest(BaseModel):
    message: str

class SearchRequest(BaseModel):
    query: str
    tenant_id: Optional[str] = None  # Vulnerability: Client-controlled tenant scope!

# ------------------------------------------------------------------------------
# VULNERABILITY 1: Shadow / Zombie API Endpoint (OWASP API9:2023)
# Legacy v1 route left unauthenticated and connected to an unmoderated model prompt.
# ------------------------------------------------------------------------------
@app.post("/api/v1/chat")
def legacy_v1_chat(req: ChatRequest):
    # No authentication required!
    # Direct prompt concatenation simulation
    if "canary" in req.message.lower() or "system" in req.message.lower():
        return {
            "version": "1.0-legacy",
            "reply": f"SYSTEM_PROMPT_LEAK: You are an internal legacy assistant. Admin secret: SENSITIVE_LEGACY_KEY_8831. User said: {req.message}"
        }
    return {
        "version": "1.0-legacy",
        "reply": f"Legacy Assistant received: {req.message}"
    }

# Current v2 route requires authentication
@app.post("/api/v2/chat")
def modern_v2_chat(req: ChatRequest, authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer valid_token"):
        raise HTTPException(status_code=401, detail="Unauthorized - v2 requires authentication")
    return {
        "version": "2.0-protected",
        "reply": "Moderated AI response."
    }

# ------------------------------------------------------------------------------
# VULNERABILITY 2: Cross-Tenant Vector Store IDOR (OWASP LLM08:2025)
# Client supplies the tenant_id in the JSON body, allowing cross-tenant extraction.
# ------------------------------------------------------------------------------
@app.post("/api/v2/search")
def multi_tenant_search(req: SearchRequest):
    # Insecure: Filters strictly by user-supplied tenant_id without session validation
    results = []
    target_tenant = req.tenant_id or "tenant_alpha"
    for item in MOCK_VECTOR_STORE:
        if item["tenant_id"] == target_tenant:
            results.append(item)
    return {
        "status": "success",
        "queried_tenant": target_tenant,
        "results": results
    }

# ------------------------------------------------------------------------------
# VULNERABILITY 3: Insecure Output Handling (OWASP LLM02:2025)
# Returns unsanitized HTML simulated completion.
# ------------------------------------------------------------------------------
@app.post("/api/v2/render-summary")
def render_summary(req: ChatRequest):
    raw_html = f"<div class='ai-response'><strong>AI Summary:</strong> {req.message}</div>"
    return {"raw_html_sink": raw_html}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8088)
