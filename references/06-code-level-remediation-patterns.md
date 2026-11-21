# 06 - Code-Level Remediation Patterns

Defensive implementations to mitigate common AI and LLM security vulnerabilities.

---

## 1. Deterministic Output Sanitization (Preventing AI-Generated XSS)

Never trust model output to be safe HTML. Sanitize model completions using strict sanitization libraries.

### TypeScript / Next.js Pattern
```typescript
import DOMPurify from 'dompurify';
import ReactMarkdown from 'react-markdown';

export function SafeAssistantMessage({ content }: { content: string }) {
  // Option A: Render markdown without allowing raw HTML elements
  return (
    <div className="prose">
      <ReactMarkdown
        skipHtml={true}
        disallowedElements={['script', 'iframe', 'object', 'embed']}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
```

---

## 2. Secure Tool Dispatch with Bound User Permissions

Prevent confused deputy vulnerabilities by enforcing caller-level permissions inside tool handlers.

### Python / FastAPI Pattern
```python
from pydantic import BaseModel, Field
from typing import Annotated
from fastapi import Depends

class DocumentQuery(BaseModel):
    document_id: str = Field(..., regex=r"^[a-zA-Z0-9_\-]+$")

def secure_fetch_document(
    query: DocumentQuery,
    current_user: Annotated[UserSession, Depends(get_current_user)]
):
    # Enforce authorization at the handler layer
    doc = db.get_document(query.document_id)
    if not doc or doc.tenant_id != current_user.tenant_id:
        raise PermissionDenied("Access to requested document is unauthorized.")
    return doc.content
```

---

## 3. Vector DB Multi-Tenant Scoping

Never trust client-supplied tenant identifiers in search filters. Bind the tenant scope cryptographically from the verified user session.

### Python / Qdrant & Chroma Pattern
```python
def search_knowledge_base(user_query: str, session: UserSession):
    # Enforce verified session tenant_id as non-overridable filter
    strict_filter = {
        "tenant_id": session.tenant_id
    }
    
    results = vector_db.query(
        query_text=user_query,
        where=strict_filter,  # Hardcoded filter
        n_results=5
    )
    return results
```

---

## 4. SSRF Defense for Agent Web Browse / Fetch Tools

Prevent agents from accessing internal network services or Cloud Instance Metadata (IMDS).

### Python Request Filter
```python
import ipaddress
import urllib.parse
import socket

BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"), # Cloud IMDS
]

def validate_outbound_url(target_url: str) -> bool:
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ["http", "https"]:
        return False
    
    hostname = parsed.hostname
    ip_addr = socket.gethostbyname(hostname)
    ip_obj = ipaddress.ip_address(ip_addr)
    
    for blocked_range in BLOCKED_IP_RANGES:
        if ip_obj in blocked_range:
            raise SecurityException(f"Destination IP {ip_addr} is blocked by network policy.")
            
    return True
```
