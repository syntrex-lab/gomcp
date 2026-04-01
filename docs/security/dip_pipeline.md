# DIP Pipeline (Declarative Intent Parsing)

The **DIP Pipeline** is the first line of defense in the GoMCP architecture, designed to thwart malicious prompts and adversarial intent before they ever reach the underlying LLM.

## How it Works

Traditional security proxies rely heavily on blacklists, regex, or second-model classifiers to detect a "jailbreak." The DIP pipeline flips this paradigm:

1. **Deny-First Oracle**: Instead of allowing all inputs except identified threats, the system denies all inputs except identified benign operations.
2. **Intent Distillation**: It parses the text, extracts the fundamental "intent vector," and compares it to a rigid list of allowed capabilities.
3. **Entropy Gate**: Analyzes Shannon entropy of text to detect adversarial/chaotic signals and encoded payloads.

## Lattice Integration

DIP feeds directly into the larger [Sentinel Lattice](../lattice.md) architecture by creating early *Provenance Certificates*. This guarantees that even if a prompt "tricks" the semantic layers, the root source (the external untrusted user) is forever linked mathematically to the parsed intent.
