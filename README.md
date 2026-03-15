# LLM Security Mini-Gateway with Presidio

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Presidio](https://img.shields.io/badge/Presidio-2.2.33-green.svg)](https://microsoft.github.io/presidio/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


A modular security gateway for Large Language Models (LLMs) that protects against prompt injection, jailbreak attempts, and sensitive information leakage using Microsoft Presidio.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/01-134241-005/LLM-security-gateway-presidio.git
cd LLM-security-gateway-presidio

# Setup environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Run tests
pytest tests/ -v

# Start gateway
python run_gateway.py --config config/config.yaml

✨ Features
Injection Detection: Identifies prompt injection and jailbreak attempts

PII Detection: Microsoft Presidio with 4 custom recognizers

Policy Engine: ALLOW/MASK/BLOCK decisions

Performance: 45.34ms avg latency, 100% accuracy on test suite
📦 Dependencies
text
presidio-analyzer==2.2.33
presidio-anonymizer==2.2.33
spacy==3.7.4
flask==3.0.2
pytest==8.0.2
