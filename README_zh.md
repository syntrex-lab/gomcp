# 🛡️ GoMCP: 适用于 AI Agent 的安全记忆核心

[🇺🇸 English](README.md) | [🇷🇺 Русский](README_ru.md) | [🇨🇳 简体中文](README_zh.md)

![Go Version](https://img.shields.io/badge/Go-1.25.0-blue.svg)
![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)
![Protocol](https://img.shields.io/badge/MCP-Supported-orange.svg)
[![Build Status](https://github.com/syntrex-lab/gomcp/actions/workflows/test.yml/badge.svg)](https://github.com/syntrex-lab/gomcp/actions)

> **"唯一具有数学证明安全性 (Sentinel Lattice) 的 RLM (递归语言模型) 记忆服务器。本地运行，全球扩展。"**  
> 属于 [Syntrex AI SOC](https://syntrex.pro) 生态系统的一部分。

**GoMCP** 是 Syntrex AI SOC 生态系统的企业级核心。它是一个完全用 Go 编写的极速、安全且持久化的模型上下文协议 (MCP) 服务器。GoMCP 为大型语言模型赋能永久演进的记忆和自我修正上下文，将标准文本代理转变为能够自我进化的持久化智能体。

*Compatible with Huawei Ascend / Kunpeng architecture (planned)*.

## 🚀 核心特性
- 🛡️ **Sentinel Lattice 保护原语:** (TSA, CAFL, GPS...) 
- ⚡ **亚毫秒级延迟:** 纯 Go 语言执行核心（可选 Rust 绑定支持）
- 🔌 **57+ 原生 MCP 工具:** 开箱即用的深度集成工具 (文件系统、Shell、Git)
- 💾 **持久化因果图谱记忆 (Causal Graph Memory):** 由强大的 SQLite 时态缓存支持的分层记忆架构 (L0-L3)

## ⚡ 快速入门

只需 30 秒即可拥有独立的 AI 记忆服务器：

```bash
# 安装
go install github.com/syntrex-lab/gomcp@latest

# 初始化
gomcp init

# 运行
gomcp serve --port 9100
```

## 🧠 应用场景
- **自主智能体 (Autonomous Agents):** 构建拥有无限且结构化记忆的智能代理。
- **安全 RAG (Secure RAG):** 具有可证明边界和基于角色权限访问的代码库查询机制。
- **本地 AI 上下文:** 使您的本地 LLM (Ollama, vLLM) 获得强大的中央上下文神经网络。

## 🏗️ 架构概览
GoMCP 是 Syntrex AI SOC 的开源底层。它主要处理记忆与编排，而企业版增加了威胁关联、可视化仪表板和合规性报告功能。

## 🛡️ 企业版 (Enterprise)
需要完整的 SOC 数据仪表板、66 个强大的 Rust 进攻引擎引擎以及分布式智能编排系统？  
查看我们的企业平台：**[Syntrex AI SOC](https://syntrex.pro)**

## 📄 许可证
根据 Apache 2.0 许可证分发。详情请参阅 [LICENSE](LICENSE) 文件。
