# GoMCP Tool Reference

GoMCP exposes a rich set of native MCP tools right out of the box, organized into several categories. These tools provide persistent memory, cognitive state management, and causal reasoning to connected Language Models.

## Memory Tools
These tools manage the Multi-level (L0-L3) Memory Hierarchy, allowing agents to persist facts across ephemeral chat sessions.

- `add_fact`: Add a new hierarchical memory fact (L0–L3). Ensures key learnings are never forgotten.
- `get_fact`: Retrieve a specific fact by its immutable ID.
- `update_fact`: Update an existing fact's content or mark it as stale.
- `delete_fact`: Delete a fact by ID.
- `list_facts`: Filter and list facts by domain (e.g., 'auth', 'database') or hierarchy level.
- `search_facts`: Full-text search across all facts.
- `list_domains`: List all unique fact domains currently known to the agent.
- `get_stale_facts`: Get facts that have been marked stale or are very old and require review.
- `get_l0_facts`: Retrieve the bedrock L0 facts (Project-level invariant facts).
- `fact_stats`: Get statistics about the fact store's size and composition.
- `process_expired`: Iterate through facts with a TTL (Time-to-Live) and trim expired ones.

## Session Tools
Session tools allow the agent to save its "cognitive state" and reload it later, surviving system restarts and context-window wipes.

- `save_state`: Save the current cognitive state vector (topics, goals, pending tasks).
- `load_state`: Load a saved cognitive state.
- `list_sessions`: List all persisted session IDs.
- `delete_session`: Delete all versions of a session.
- `restore_or_create`: Quick tool to either restore the most recent state or start fresh.
- `get_compact_state`: Retrieve a compressed summary of the state suited for prompt injection.
- `get_audit_log`: Extract the immutable decision audit log for the current session.

## Causal Reasoning Tools
Tools for modeling decisions mathematically.

- `add_causal_node`: Add a node to the reasoning graph (decision, reason, consequence, constraint, alternative, assumption).
- `add_causal_edge`: Connect nodes (justifies, causes, constrains).
- `get_causal_chain`: Query the chain of decisions that led to a specific state.
- `causal_stats`: View causal store sizing statistics.

## Crystal & Operations
These tools deal with underlying system status and code primitive indexing.

- `search_crystals`: Search code crystals (abstracted AST representations of code primitives).
- `get_crystal`: Retrieve a code crystal.
- `list_crystals`: List all indexed code crystals.
- `crystal_stats`: Sizing of the code crystal index.
- `health`: Check GoMCP health metrics.
- `version`: Server build version and git commit hash.
- `dashboard`: Get aggregate statistics across all subsystems.

*There are an additional 11 NLP-based bridging tools available if GoMCP is run with the `-bridge-script` flag for Python integration.*
