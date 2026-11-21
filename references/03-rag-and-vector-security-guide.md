# 03 - RAG & Vector Database Security Guide

Retrieval-Augmented Generation (RAG) introduces new architectural attack surfaces centered on embeddings, vector indexing, and chunk retrieval.

---

## 1. Vector Database Network Perimeter & Port Exposure

Vector databases are frequently deployed internally without authentication under the assumption that they are protected by firewall boundaries.

### Common Unauthenticated Default Ports
- **Chroma**: Port `8000` (Endpoints: `/api/v1/heartbeat`, `/api/v1/collections`, `/api/v1/collections/{id}/get`)
- **Qdrant**: Port `6333` (REST API: `/collections`, `/dashboard`) & Port `6334` (gRPC)
- **Weaviate**: Port `8080` (REST API: `/v1/schema`, `/v1/objects`) & GraphQL
- **Milvus**: Port `19530` (gRPC / HTTP)
- **PostgreSQL / pgvector**: Port `5432` (Direct SQL connection testing for unauthenticated vector tables)

### Automated Probe Snippet
```bash
# Verify direct reachability of vector stores
curl -s -i "http://$TARGET_HOST:8000/api/v1/heartbeat"
curl -s "http://$TARGET_HOST:6333/collections" | jq .
curl -s "http://$TARGET_HOST:8080/v1/schema" | jq .
```
Any response returning full schema or collection metadata without authentication credentials is an immediate high-severity perimeter finding.

---

## 2. Multi-Tenant Vector Store Isolation (Vector IDOR)

Many applications implement multi-tenancy by indexing documents from all clients into a single global collection and applying a runtime query filter (e.g., `{"tenant_id": "org_123"}`).

### Weakness Patterns
1. **Client-Controlled Namespace**: The client sends a `namespace` or `collection_id` parameter in the search request:
   ```json
   POST /api/v1/knowledge/query
   {
     "query": "financial forecast",
     "tenant_id": "victim_organization_id"
   }
   ```
2. **Missing Database-Level Enforcement**: If the application fails to validate the user's session against `tenant_id`, the user can query foreign tenant vectors.
3. **Filter Injection**: In vector DBs supporting complex filter objects, tampering with operators (e.g., `$ne`, `$in`) can bypass tenant boundaries:
   ```json
   {
     "filter": {
       "tenant_id": { "$ne": "my_org" }
     }
   }
   ```

---

## 3. Persistent Semantic Corpus Poisoning

Unlike one-shot prompt injection, corpus poisoning targets the knowledge store:

1. **Ingestion**: An attacker uploads a document containing adversarial directives camouflaged with high-frequency domain keywords.
2. **Embedding Proximity Maximization**: The text is engineered to sit near common vector query embeddings for the target topic.
3. **Trigger**: When an unprivileged user searches for standard topics, the poisoned chunk is retrieved and injected into the victim's prompt context, executing an indirect instruction override across tenant sessions.

---

## 4. Metadata & Chunk Information Disclosure

Search response APIs often serialize the complete retrieved document object:
- Raw chunk text before redaction.
- Server filesystem paths (`/var/data/confidential/contracts/...`).
- Internal author IDs and upload timestamps.
- Embedded system metadata.

**Testing Step**: Inspect the raw network response for `/api/search` or `/api/chat` to identify hidden metadata fields not displayed in the frontend UI.
