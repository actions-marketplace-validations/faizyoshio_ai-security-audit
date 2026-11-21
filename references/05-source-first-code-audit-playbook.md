# 05 - Source-First Code Audit Playbook

This guide covers static and architectural analysis of AI applications built on frameworks such as LangChain, LlamaIndex, Vercel AI SDK, AutoGen, and CrewAI.

---

## 1. Threat Modeling the AI Data Flow

A source-first audit traces data across five critical boundaries:

```
[Untrusted Input] ──> [Prompt Assembly] ──> [Model Inference] ──> [Tool Dispatch] ──> [Output Sinks]
       │                       │                     │                   │                   │
  Untrusted Data         String Injection      Context Leakage      SSRF / Exec        Stored XSS / SQLi
```

1. **Untrusted Input**: User chat messages, uploaded files, third-party webhook payloads, scraped web pages.
2. **Prompt Assembly**: String formatting or message role array construction.
3. **Model Inference**: Temperature, model choice, system instructions, token caps.
4. **Tool Dispatch**: Schema parsing, permission checking, argument normalization, external service calls.
5. **Output Sinks**: Web UI rendering, database persistence, email dispatch, command execution.

---

## 2. Framework-Specific Audit Checkpoints

### Python (LangChain / LlamaIndex / FastAPI)
- **Direct String Formatting in Prompts**:
  - *Risk*: `f"You are an assistant. User said: {user_input}"` loses message role boundaries.
  - *Secure Pattern*: Use structured chat templates with distinct `SystemMessage`, `HumanMessage`, and `AIMessage` classes.
- **Unsafe Tool Execution**:
  - Check tools marked with `@tool` or `FunctionTool`.
  - Look for tools executing SQL (`SQLDatabaseChain`), system commands (`BashProcess`), or file reads (`FileSearchTool`).
  - *Vulnerability*: The tool executes actions using server credentials without re-validating the end user's authorization.

### TypeScript / JavaScript (Vercel AI SDK / Node.js)
- **Streaming Response Sinks**:
  - Check how stream completions are rendered:
    ```typescript
    // Insecure
    <div dangerouslySetInnerHTML={{ __html: completion }} />
    ```
  - *Vulnerability*: Stored XSS triggered by model output.
  - *Secure Pattern*: Parse through an escaped markdown renderer with strict DOMPurify hooks.

---

## 3. Human-in-the-Loop (HITL) Action Binding

Verify that state-changing agent actions cannot execute autonomously:

- **Missing Approval Check**: Actions that mutate user records, transfer balances, or invoke external APIs must pause and request explicit user confirmation.
- **Action Tampering**: When confirmation is requested, ensure the approved action and arguments cannot be modified by subsequent model turns or prompt injections.
