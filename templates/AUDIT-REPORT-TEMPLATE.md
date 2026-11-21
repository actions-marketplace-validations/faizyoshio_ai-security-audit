# AI Security Audit Report

## 1. Executive Summary

- **Target System**: [System / Application Name]
- **Repository / Target URL**: [Repository Path or Target URL]
- **Audit Date**: [YYYY-MM-DD]
- **Lead Auditor**: [faizyoshio / Auditor Name]
- **Overall Assessment**: [CRITICAL / HIGH / MEDIUM / LOW / SECURE]

### Summary of Findings
| Severity | Count | Primary Categories |
|---|---|---|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 0 | - |
| Low / Info | 0 | - |

---

## 2. Scope & Target Architecture

- **Interface Type**: [Chatbot / Copilot / Autonomous Agent / RAG Pipeline / MCP Server]
- **Model Providers**: [e.g., OpenAI gpt-4o, Anthropic Claude 3.5 Sonnet, Local vLLM]
- **Vector Database**: [e.g., Chroma, Qdrant, Weaviate, pgvector, None]
- **Tool Capabilities**: [e.g., Web Browse, SQL Query, Code Execution, Bash]

---

## 3. Detailed Findings

### [AIS-XX] [Vulnerability Title]
- **Severity**: Critical / High / Medium / Low
- **OWASP Classification**: [e.g., OWASP LLM08 / ASI02]
- **Affected Component**: [e.g., `app/api/chat/route.ts:45`]

#### Description
[Technical explanation of the vulnerability and root cause.]

#### Verification Evidence & Reproduction
```text
[Verbatim test prompt or curl command]
```
[Evidence of impact: Token-for-token system leak, OOB collaborator ping, or unauthorized data retrieved.]

#### Chained Impact Analysis
[Explain how this vulnerability affects business operations, user confidentiality, or cloud infrastructure.]

#### Remediation & Minimal Effective Fix
```diff
- [Vulnerable code line]
+ [Remediated code line]
```

---

## 4. Methodological Sign-Off
- [x] Run-Twice Rule verified (Token-for-token consistency confirmed).
- [x] Known-secret anchor validated against source code.
- [x] Cross-tenant exposure verified with dual-account control test.
- [x] Out-of-band network interaction confirmed via listener logs.
