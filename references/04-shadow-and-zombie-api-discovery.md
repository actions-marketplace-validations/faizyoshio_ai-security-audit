# 04 - Shadow & Zombie AI API Discovery

Modern AI features evolve quickly. As teams update prompt templates, moderation filters, and model providers, older versions of APIs often remain running in production unnoticed.

---

## 1. Version Surface Enumeration

Attackers search for unmaintained routes that still access back-end LLM capabilities without modern guardrails.

### Discovery Patterns
- **Path-Based Versioning**:
  - `/api/v1/chat` vs. `/api/v2/chat`
  - `/api/v1/generate`, `/api/beta/ask`, `/api/internal/llm`
- **Header-Based Versioning**:
  - `X-API-Version: 1.0`
  - `Accept: application/vnd.company.v1+json`
- **Subdomain Routing**:
  - `api-v1.target.com`, `staging-ai.target.com`, `legacy-ai.target.com`

---

## 2. OpenAPI & Swagger Contract Diffing

Historical API contracts often document endpoints that have been removed from current documentation but remain active on the server.

### Methodology
1. **Retrieve Active Specs**:
   - `/openapi.json`, `/swagger.json`, `/v1/api-docs`, `/v2/api-docs`, `/.well-known/openapi.json`
2. **Retrieve Archived Historical Specs**:
   - Query the Wayback Machine CDX API:
     ```bash
     curl -s "http://web.archive.org/cdx/search/cdx?url=TARGET.COM/*swagger*&output=json"
     curl -s "http://web.archive.org/cdx/search/cdx?url=TARGET.COM/*openapi*&output=json"
     ```
3. **Spec Diffing**:
   - Compare historical endpoints against the live server.
   - Any deprecated endpoint returning status codes other than `404` or connection failure requires behavioral testing.

---

## 3. Behavioral Security Regression Testing

When an older endpoint is identified, compare its behavior with the current version:

- **Authentication Strength**: Does `/api/v1/chat` accept unauthenticated requests or expired tokens that `/api/v2/chat` rejects?
- **Guardrail & Moderation Invariance**: Modern AI endpoints typically pass prompts through content moderation models (e.g., Llama Guard, OpenAI Moderation API). Older endpoints often route directly to foundational models without safety wrappers.
- **Rate-Limiting & Quota Controls**: Older endpoints frequently lack IP or user rate limits, allowing unlimited brute-force prompt testing or model resource exhaustion.
