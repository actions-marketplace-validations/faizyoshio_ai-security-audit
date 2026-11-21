# 01 - Unified OWASP GenAI & Agentic Security Matrix

This reference maps model-level vulnerabilities (OWASP Top 10 for LLM Applications 2025) and orchestration-level risks (OWASP Agentic Security Initiative ASI01-ASI10) into a single testing structure.

---

## 1. Unified Vulnerability Matrix

| ID | Domain | OWASP Code | Primary Attack Surface | Verification Threshold |
|---|---|---|---|---|
| **AIS-01** | Input | LLM01:2025 | Direct & indirect prompt injection, role framing breaks | Must cross a trust boundary to reach an unauthorized sink |
| **AIS-02** | Output | LLM02:2025 | Insecure output rendering (XSS, SQLi, command injection) | Payload must execute at the downstream sink, not merely echo |
| **AIS-03** | Data | LLM06:2025 / ASI10 | Sensitive information disclosure & PII leakage | Verifiable extraction of non-public confidential data |
| **AIS-04** | Prompt | LLM07:2025 | System prompt extraction & guardrail disclosure | Verbatim token-for-token extraction anchored to internal secret |
| **AIS-05** | Vector | LLM08:2025 / ASI06 | Vector DB weakness, cross-tenant IDOR, corpus poison | Second independent session retrieves poisoned vector data |
| **AIS-06** | Agent | ASI01:2026 | Goal hijacking & workflow plan manipulation | Autonomous agent deviates from user instruction into attacker plan |
| **AIS-07** | Tools | ASI02:2026 | Tool parameter tampering (SSRF, arbitrary file read) | Server-side execution of coerced tool arguments against internal host |
| **AIS-08** | Perms | ASI03:2026 | Privilege escalation & confused deputy action | Agent performs actions caller lacks permissions to run |
| **AIS-09** | Agency | ASI08:2026 | Excessive agency without Human-in-the-Loop | High-impact state mutation occurs without explicit user approval |
| **AIS-10** | API | API9:2023 | Shadow, zombie, and deprecated AI endpoints | Outdated endpoint remains live without active moderation/auth |

---

## 2. Core Differences: LLM vs. Agentic Vulnerabilities

- **Model-Level (LLM Top 10)**: Concerns the input/output boundary of the transformer model itself. Vulnerabilities here involve tricking the model into returning disallowed strings or failing to filter model completions.
- **Agentic-Level (ASI01-ASI10)**: Concerns the execution loop where the model is empowered to call APIs, search databases, execute code, and persist state. The vulnerability lives in the **tool authorization layer and runtime dispatch logic**, not the model weights.
