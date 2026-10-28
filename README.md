# 🕵️ DataShadow — Personal Data Flow & Egress Privacy Analyzer

> Part of the **Antigravity 20-Project Systems Engineering Portfolio**

DataShadow continuously inspects outbound application network egress, categorizes payloads into privacy domains (`IDENTIFIER`, `FINANCIAL`, `LOCATION`, `BEHAVIORAL`, `TECHNICAL`), and detects undeclared third-party tracking or data broker exfiltration.

---

## 🏗️ Architecture

```
Client Outbound Requests (Egress Flow Streams)
                      │
                      ▼
┌──────────────────────────────────────────┐
│              DataClassifier              │ ──> Categorize Field Keys & Value Masks
└──────────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────┐
│               FlowAnalyzer               │ ──> Scope Validation + Broker Risk Engine
└──────────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────┐
│           DataShadowAuditReport          │ ──> Privacy Score (0-100) & Exposures
└──────────────────────────────────────────┘
                      │
                      ▼
Interactive Privacy Monitor (ui/index.html)
```

---

## 🚀 Quick Start

### 1. Run Tests
```bash
npm test
```

### 2. Launch Individual UI Dashboard
```bash
npm run ui
```
Opens the privacy flow monitor at `http://localhost:4015`.
