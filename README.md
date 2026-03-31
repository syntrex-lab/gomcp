# GoMCP: Recursive Language Model Server

![Go Version](https://img.shields.io/badge/Go-1.25.0-blue.svg)
![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)
![Protocol](https://img.shields.io/badge/MCP-Supported-orange.svg)

> **The only Open-Source RLM (Recursive Language Model) Memory Server with Mathematically Proven Safety.**

GoMCP is the enterprise core of the Syntrex AI SOC ecosystem. It is an extremely fast, secure, and persistent Model Context Protocol (MCP) server entirely written in Go. GoMCP gives Large Language Models a permanent, evolving memory and self-modifying context, transforming standard text agents into self-improving persistent intelligences. 

## 🚀 Key Features
- **Context Consciousness Crystal (C³):** Hierarchical memory layers (L0-L3) combined with SQLite-backed temporal caching.
- **57+ Native MCP Tools:** Deeply integrated tools for agentic self-reflection, codebase navigation, and file editing. 
- **Sub-millisecond latency:** Engineered for speed and durability under enterprise loads.
- **Secure by Default:** Zero-G execution environment and robust isolation from the main operating system logic. DoH shielding, uTLS protocols, and session resumption natively integrated.

## ⚡ Quick Start

Install GoMCP as an independent memory server in 30 seconds:

```bash
go install github.com/syntrex-lab/gomcp/cmd/gomcp@latest
```

Initialize your RLM context inside a workspace:

```bash
gomcp init
gomcp serve --port 9100
```

## 🧠 Use Cases
- **Autonomous Agents:** Build agents with infinite, structured memory.
- **Secure RAG:** Query codebases with provable bounds and role-based clearance. 
- **Local AI Context:** Supercharge your local LLMs (Ollama, vLLM) with a centralized context nervous system.

## 🛡️ Enterprise CTA
Need a full SOC dashboard, 66 offensive Rust engines, and distributed intelligence orchestration?  
Check out our enterprise platform: **[Syntrex AI SOC](https://syntrex.pro)**

## License
Licensed under Apache 2.0 – Free for commercial and private use.
