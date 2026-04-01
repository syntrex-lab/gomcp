# Capability-Attenuating Flow Labels (CAFL)

**CAFL** is a genuinely new defense primitive introduced by Sentinel Lattice within the GoMCP architecture. While existing Information Flow Control (IFC) mechanisms assume deterministic programs, CAFL operates on the assumption that an LLM can perform **any** information transformation (worst-case taint propagation).

## Attenuation Over Time

Every data object in the GoMCP execution context carries a set of *capability labels* (e.g., `{read, process, transform, export, delete}`). CAFL enforces a unidirectional rule: **Capabilities can only DECREASE across boundaries.**

### Example Flow

1. **Tool Output Returns Sensitive Data**
   `file_read(.env) -> output features capabilities: {process, display}`
   *(Note the lack of the `{export}` capability.)*
2. **LLM Interaction**
   The LLM parses the data and returns a response. The response inherently inherits the *most restrictive* (most attenuated) capabilities of all inputs it consumed.
3. **Execution Block**
   If the LLM now attempts a tool call:
   `email_send(body: LLM_response) -> operation requires {export}`
   Because the `.env` data attenuated the flow's capabilities (removing `{export}`), the chain is **BLOCKED**.

## The Membrane Pattern

Trust boundary crossings inherently attenuate capabilities unless explicitly authorized by the developer:

- **Internal → External:** Removes `{export}`
- **User → System:** Removes `{modify_config}`
- **Session → Persistent:** Removes `{ephemeral}`

This means that even if a prompt injection tricks the LLM into initiating an exfiltration attempt, the mathematical capabilities of the data prevent the outbound network call.

See the full mathematical foundation in the [Sentinel Lattice Architecture Specification](../lattice.md).
