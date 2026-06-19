# Network Bouncer

## AI-Powered Detection of Suspicious Port Scanning in Data Center Traffic

Network Bouncer is a cybersecurity analytics platform designed to detect suspicious port-scanning behavior in data center environments. The system analyzes network traffic logs, identifies anomalous communication patterns, and provides actionable insights to security analysts through risk scoring and visual reporting.

This project is being developed as part of the Dell Futureminds AI Hackathon.

---

## Problem Statement

In modern data centers, compromised machines often attempt to communicate with a large number of hosts and ports within a short period of time. This behavior, known as port scanning, is frequently one of the earliest indicators of malware propagation, reconnaissance, or unauthorized network activity.

The objective of this project is to analyze network traffic data and identify suspicious hosts by detecting abnormal connection patterns and classifying network behavior as either normal or suspicious.

---

## Key Features

* Network traffic log parsing
* Feature extraction from connection metadata
* Port scanning detection engine
* Explainable anomaly detection
* Risk scoring and severity classification
* Security-focused dashboard
* Suspicious host reporting
* Exportable analysis results

---

## Proposed Architecture

```text
Network Traffic Dataset
          │
          ▼
    Data Parser
          │
          ▼
 Feature Extraction
          │
          ▼
  Detection Engine
     ├── Rule-Based Detection
     └── Anomaly Detection
          │
          ▼
     Risk Scoring
          │
          ▼
 Security Dashboard
          │
          ▼
  Reports & Insights
```

---

## Technology Stack

### Programming Language

* Python

### Data Processing

* Pandas
* NumPy

### Machine Learning

* Scikit-Learn

### Visualization

* Streamlit
* Plotly
* Matplotlib

### Version Control

* Git
* GitHub

---

## Project Structure

```text
network-bouncer/

├── data/
│   ├── raw/
│   └── processed/
│
├── src/
│   ├── parser/
│   ├── features/
│   ├── detection/
│   ├── reporting/
│   └── dashboard/
│
├── notebooks/
├── docs/
├── screenshots/
├── tests/
│
├── requirements.txt
├── README.md
└── main.py
```

---

## Team

| Name            | Role                      |
| --------------- | ------------------------- |
| Raj Rathaur     | Team Lead                 |
| Anjali Kumari   |                           |
| Vanshika Dixit  |                           |
| Sonam Sharma    |                           |
| Prashant Sharma |                           |

---

## Goals

* Detect suspicious port-scanning activity
* Minimize false positives
* Provide explainable security insights
* Build an analyst-friendly monitoring interface
* Create a scalable and maintainable solution

---

## Current Status

🚧 Project Initialization Phase

* [ ] Dataset Analysis
* [ ] Feature Engineering
* [ ] Detection Logic Design
* [ ] Dashboard Development
* [ ] Testing & Evaluation
* [ ] Final Presentation

---

## License

This project is developed for educational and hackathon purposes.
