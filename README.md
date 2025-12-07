# 🛡️ Solidity Smart Contract AI Auditor Prompt

This repository contains a specialized system prompt designed to turn LLMs (like Gemini 3 pro, Claude 4.5 Opus etc.) into rigorous Solidity Smart Contract Auditors.

## 🚀 Overview

The goal of this prompt is to detect high-severity vulnerabilities, hidden backdoors, and malicious patterns (honeypots) in Solidity code. It forces the AI to act as a seasoned security researcher with a "malicious owner" mindset.

## ✨ Features

The prompt is engineered to detect **14 specific vulnerability categories**, including:
- 🚨 **Hidden Minting:** Unauthorized token creation.
- 🎭 **Hidden Owner:** Privileged access disguised behind obscure logic.
- 🪤 **Honeypot Mechanisms:** Pause transfers, blacklists, anti-whale traps.
- 💸 **Fee Manipulation:** Ability to change fees to 100%.
- 🧩 **Obfuscation:** Code designed to hide logic.

## 📋 Usage

1. Copy the content of [SOL_AUDITOR_PROMPT.md](SOL_AUDITOR_PROMPT.md).
2. Paste it into your preferred LLM (ChatGPT, Claude, Gemini).
3. The AI will acknowledge the prompt and ask for the Solidity code.
4. Paste the contract code you want to analyze.
5. Receive a structured JSON report detailing any findings.

## ⚠️ Disclaimer

**This tool is for educational and research purposes only.** AI analysis allows for rapid screening but is not a substitute for a professional human audit. Always verify findings manually.

## 📄 License

MIT
