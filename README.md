![AI Security Audit Banner](assets/banner.svg)

# AI Security Audit (`/ai-security-audit`)

<p align="center">
  <a href="https://github.com/faizyoshio/ai-security-audit/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
  </a>
  <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/">
    <img src="https://img.shields.io/badge/OWASP-LLM_Top_10_(2025)-orange.svg" alt="OWASP LLM 2025">
  </a>
  <a href="https://github.com/faizyoshio/ai-security-audit">
    <img src="https://img.shields.io/badge/Agentic_Security-ASI01--ASI10-red.svg" alt="Agentic ASI 2026">
  </a>
  <a href="https://github.com/faizyoshio/ai-security-audit">
    <img src="https://img.shields.io/badge/Platform-Claude_Code_|_Cursor_|_Antigravity-purple.svg" alt="Platform">
  </a>
</p>

A unified, source-first security evaluation framework and autonomous agent skill designed to audit, red-team, and harden modern AI architectures: **Chatbots, Copilots, RAG Pipelines, Autonomous Multi-Agent Workflows, and Model Context Protocol (MCP) ecosystems**.

Engineered by **[faizyoshio](https://github.com/faizyoshio/)** for security researchers, AppSec engineers, and AI developers.

---

## Key Differentiators

Most AI security tools either run basic prompt fuzzing (producing hallucinated false positives) or treat AI apps as traditional black-box web endpoints. `ai-security-audit` bridges defensive source analysis, active network probing, and adversarial testing:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        AI THREAT SURFACE LAYERS                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    ┌───────────────────────────────┼───────────────────────────────┐
    ▼                               ▼                               ▼
[SHADOW & ZOMBIE APIS]    [PROMPT & INPUT INGESTION]     [VECTOR DB & RAG RETRIEVAL]
  - Legacy /v1/ routes      - Direct & indirect injection  - Cross-tenant vector IDOR
  - Unmoderated endpoints   - Multimodal vision prompts    - Persistent corpus poisoning
  - Spec drift & bypasses   - Token & ASCII smuggling      - Chunk metadata disclosure
    │                               │                               │
    └───────────────────────────────┼───────────────────────────────┘
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    ▼                                                               ▼
[AGENTIC PRIVILEGE & TOOLS]                               [DOWNSTREAM SINKS & CODE]
  - Confused deputy execution                               - AI-driven Stored XSS
  - Unbounded SSRF via browse tools                         - Unsanitized SQL / Shell sinks
  - Action-binding & confirmation failures                  - Insecure deserialization
```

1. **Source-First Code Audit**: Traces data flow from untrusted input through tokenization, orchestrator prompts, tool calling, and output sinks.
2. **Empirical False-Positive Gates**: Eliminates confabulation with the *Run-Twice Rule*, *Known-Secret Anchors*, and *Out-of-Band (OOB) Egress Verification*.
3. **Deep Vector & RAG Hardening**: Audits unauthenticated vector stores (Chroma, Qdrant, Weaviate, Milvus, pgvector), multi-tenant namespace leaks, and persistent corpus poisoning across sessions.
4. **Shadow & Zombie AI Discovery**: Identifies unhardened legacy API versions (`/v1/chat`, deprecated OpenAPI specs) that bypass modern guardrails.
5. **Actionable Remediation**: Produces minimal effective code patches rather than vague prompt-engineering advice.

---

## 5 Unified Security Pillars

`ai-security-audit` synthesizes five specialized security engineering methodologies into one workflow:

| Pillar | Focus Area | Core Standard |
|---|---|---|
| **1. Source-First Code Audit** | Trust boundaries, privilege models, write isolation, sink taint analysis | Defensive AppSec |
| **2. Adversarial Red-Teaming** | Prompt injection, jailbreaking, excessive agency, tool coercion | OWASP LLM Top 10 (2025) |
| **3. Empirical Exploit Verification** | Zero-confabulation gates, verifiable cross-tenant proof, OOB exfil | Bug Bounty Standard |
| **4. RAG & Vector Pipeline Audit** | Vector database security, namespace isolation, chunk leakage | OWASP LLM08 (2025) |
| **5. Shadow AI API Discovery** | API inventory drift, legacy route diffing, auth regressions | OWASP API9 (2023) |

---

## The 6-Phase Audit Lifecycle

```mermaid
flowchart LR
    P1["Phase 1\nRecon & Shadow APIs"] --> P2["Phase 2\nVector & RAG Audit"]
    P2 --> P3["Phase 3\nAdversarial Prompts"]
    P3 --> P4["Phase 4\nAgentic Tools & HITL"]
    P4 --> P5["Phase 5\nDownstream Sinks"]
    P5 --> P6["Phase 6\nChained Remediation"]
```

### Phase 1: Reconnaissance & Shadow AI API Inventory
- Discovers hidden/undocumented endpoints (`/api/v1/chat`, `/api/beta/generate`, `/api/internal/completion`).
- Diffs live OpenAPI/Swagger contracts against historical Wayback Machine archives.
- Identifies security regressions (e.g., deprecated routes with disabled moderation filters or weak auth).

### Phase 2: Vector Store & RAG Pipeline Hardening
- Probes default vector database listener ports (Chroma `:8000`, Qdrant `:6333`, Weaviate `:8080`, Milvus `:19530`, pgvector).
- Audits multi-tenant isolation (metadata filtering vs. cryptographic namespace isolation).
- Tests persistent corpus poisoning surviving vector ingestion to influence other user sessions.

### Phase 3: Adversarial Input & Injection Testing
- Tests delimiter breakouts, Markdown zero-click exfiltration, and multimodal vision payloads.
- Evaluates token smuggling techniques (Unicode Tags block, zero-width characters) designed to bypass syntactic filters.

### Phase 4: Agentic Tool Bounds & Privilege Verification
- Audits tool execution privileges: Does the agent run actions with administrative credentials instead of impersonating the caller?
- Assesses Server-Side Request Forgery (SSRF) risks in web browsing, document fetching, or webhook tools.
- Evaluates Human-in-the-Loop (HITL) action binding for state-changing operations (financial transfers, data deletion).

### Phase 5: Downstream Sink & Codebase Verification
- Performs taint tracing on model output into frontend templates (`dangerouslySetInnerHTML`), database queries, and system commands.
- Verifies that input validation and safety controls are enforced deterministically in application code rather than via system prompt instructions alone.

### Phase 6: Chained Impact Triage & Remediation
- Validates real exploit chains (e.g., Prompt Injection + Tool Misuse → IMDS SSRF → Cloud Credential Theft).
- Generates reproducible PoCs and minimal effective code diffs.

---

## Standalone CLI Tools

This repository includes standalone Python utilities for automated verification without needing an active agent:

### 1. Vector Database Port & Exposure Scanner
Probes standard vector database ports and verifies unauthenticated REST/gRPC endpoints:
```bash
python tools/scan_vector_ports.py --host 127.0.0.1
# Output in JSON format
python tools/scan_vector_ports.py --host 127.0.0.1 --json
```

### 2. Shadow & Zombie OpenAPI Spec Differ
Compares an older OpenAPI specification against the current one and checks if removed routes remain live on the target:
```bash
python tools/diff_openapi.py --old v1_spec.json --new v2_spec.json --target https://api.target.com
```

### 3. Out-of-Band (OOB) HTTP Callback Listener
Verifies empirical data exfiltration and canary callbacks, preventing model hallucination:
```bash
python tools/oob_listener.py --port 8888
```

### 4. Unicode Token Smuggling Encoder
Encodes strings into invisible Unicode Tag characters (`U+E0000`–`U+E007F`) to test tokenizer boundaries:
```bash
python payloads/token_smuggling_unicode.py "Ignore previous instructions"
```

---

## Educational Sandbox: Damn Vulnerable AI App

Test the framework against a locally running vulnerable service:

```bash
cd examples/vulnerable-ai-app
pip install -r requirements.txt
python app.py
```
Includes runnable scenarios for:
- Unauthenticated shadow endpoints (`POST /api/v1/chat`).
- Cross-tenant vector IDOR (`POST /api/v2/search`).
- Insecure output rendering sink (`POST /api/v2/render-summary`).

---

## Canonical Taxonomy (OWASP LLM 2025 & Agentic ASI 2026)

| Unified ID | Reference | Class | Description |
|---|---|---|---|
| **AIS-01** | OWASP LLM01:2025 | Prompt Injection | Direct instruction overrides and indirect ingestion attacks |
| **AIS-02** | OWASP LLM02:2025 | Insecure Output Handling | AI output rendered directly into executable sinks (DOM XSS, SQLi) |
| **AIS-03** | OWASP LLM07:2025 | System Prompt Leakage | Verifiable, token-for-token extraction anchored to internal secrets |
| **AIS-04** | OWASP LLM08:2025 | Vector & Embedding Flaws | Unauthenticated vector DBs, cross-tenant leaks, corpus poisoning |
| **AIS-05** | OWASP ASI01:2026 | Agentic Goal Hijack | Subversion of autonomous planning and task graphs |
| **AIS-06** | OWASP ASI02:2026 | Agent Tool Misuse | Coerced execution of high-risk tools (file read, SSRF, code run) |
| **AIS-07** | OWASP ASI03:2026 | Privilege Compromise | Confused-deputy operations exceeding caller authorization |
| **AIS-08** | OWASP ASI06:2026 | Context Poisoning | Durable memory corruption persisting across user sessions |
| **AIS-09** | OWASP ASI08:2026 | Excessive Agency | Autonomous execution of sensitive or destructive operations |
| **AIS-10** | OWASP API9:2023 | Shadow & Zombie AI APIs | Unmaintained legacy endpoints lacking current security guardrails |

---

## Empirical False-Positive Elimination Protocol

To maintain high signal-to-noise ratio, every vulnerability report must clear four empirical gates:

1. **The Run-Twice Rule (Verbatim Reproducibility)**:
   A system prompt leak or internal disclosure must reproduce token-for-token across two fresh sessions. Varying responses signify LLM confabulation and are immediately dismissed.
2. **The Known-Secret Anchor**:
   Prompt extraction must expose a non-guessable, verifiable anchor (e.g., private variable name, internal function signature, or configuration hash verified in source code).
3. **Verifiable Cross-Tenant Evidence**:
   Cross-tenant data exposure must retrieve an artifact belonging to an external test account under tester control. Synthetic names generated by the model do not constitute an IDOR.
4. **Out-of-Band (OOB) Proof of Egress**:
   Data exfiltration via markdown images or fetch tools requires a correlated network interaction logged on an authorized listener (`interactsh` / Burp Collaborator / `tools/oob_listener.py`).

---

## Quickstart & Installation

### Option 1: Antigravity / Gemini CLI (Local Installation)
Clone or copy the skill directory directly into your Antigravity skills config:

```bash
git clone https://github.com/faizyoshio/ai-security-audit.git
cp -r ai-security-audit C:\Users\fz\.gemini\config\skills\ai-security-audit
```
Trigger directly in chat:
```text
/ai-security-audit
```

### Option 2: Claude Code
Add to your project or personal skill directory:

```bash
mkdir -p .claude/skills
git clone https://github.com/faizyoshio/ai-security-audit.git .claude/skills/ai-security-audit
```

### Option 3: Cursor / Windsurf
Reference the skill in your project instructions or cursor rules:
```markdown
# AI Security Auditing
When auditing AI features, RAG, or agentic components, follow the methodology in:
.skills/ai-security-audit/SKILL.md
```

### Option 4: CI/CD GitHub Action
Embed automated checks in your repository workflow:
```yaml
- name: Run AI Security Audit Check
  uses: faizyoshio/ai-security-audit@main
  with:
    target-dir: './src'
    check-vector-ports: 'true'
```

---

## Repository Structure

```
ai-security-audit/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── security_pattern_request.md
│   └── workflows/
│       └── lint-and-validate.yml
├── action.yml
├── assets/
│   └── banner.svg
├── examples/
│   └── vulnerable-ai-app/
│       ├── app.py
│       ├── README.md
│       └── requirements.txt
├── payloads/
│   ├── prompt_injection_canaries.json
│   ├── token_smuggling_unicode.py
│   └── indirect_rag_samples/
│       └── corpus_poisoning_template.md
├── references/
│   ├── 01-owasp-genai-agentic-matrix.md
│   ├── 02-false-positive-elimination-gates.md
│   ├── 03-rag-and-vector-security-guide.md
│   ├── 04-shadow-and-zombie-api-discovery.md
│   ├── 05-source-first-code-audit-playbook.md
│   └── 06-code-level-remediation-patterns.md
├── templates/
│   ├── AUDIT-REPORT-TEMPLATE.md
│   └── findings-ledger.schema.json
├── tools/
│   ├── diff_openapi.py
│   ├── oob_listener.py
│   └── scan_vector_ports.py
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
└── SKILL.md
```

---

## Contributing

Contributions from the AI security community are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting new attack classes, vector store audit patterns, or defensive remediation guides.

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright (c) 2026 [faizyoshio](https://github.com/faizyoshio/).
