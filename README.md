# 🔒 LLM Security Gateway - Presidio-Based

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Presidio](https://img.shields.io/badge/Presidio-2.2.33-green.svg)](https://microsoft.github.io/presidio/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📋 Assignment Information
- **Course:** Artificial Intelligence (AIC201) - Assignment 2 [CLO-2]
- **Instructor:** Dr. Arshad Farhad
- **Project:** Presidio-Based LLM Security Mini-Gateway

## 🎯 Overview
A security gateway that protects LLM-based systems from:
- Prompt Injection Attacks
- Jailbreak Attempts
- System Prompt Extraction
- PII Leakage
- API Key/Secret Exposure

## 🏗️ Architecture
User Input → Injection Detection → Presidio Analyzer → Policy Decision → Output


## ✨ Features
- ✅ Prompt injection & jailbreak detection with scoring
- ✅ PII detection using Microsoft Presidio
- ✅ 3+ custom Presidio recognizers
- ✅ Context-aware scoring
- ✅ Composite entity detection
- ✅ Confidence calibration
- ✅ Configurable policies (Allow/Mask/Block)
- ✅ Latency measurement
- ✅ Comprehensive evaluation tables

llm-security-gateway-presidio/
├── README.md
├── requirements.txt
├── setup.py
├── config/
│   ├── settings.py
│   └── thresholds.yaml
├── src/
│   ├── gateway.py
│   ├── detectors/
│   │   └── injection_detector.py
│   ├── presidio/
│   │   ├── custom_recognizers.py
│   │   └── composite_entities.py
│   ├── policies/
│   │   └── decision_engine.py
│   └── utils/
│       ├── metrics.py
│       └── latency.py
├── evaluation/
│   ├── generate_tables.py
│   └── test_cases.csv
├── tests/
│   └── test_detectors.py
└── bonus/
    ├── ollama_integration.py
    └── llm_backend.py
