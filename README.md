# Network Bouncer

Network Bouncer is a Python-based cybersecurity analytics tool that detects suspicious scan-like behavior in network traffic data. It was built for the Dell hackathon use case of identifying machines that contact many destinations, try many ports, or show abnormal connection patterns.

The current implementation provides a working command-line pipeline:

```text
CSV input -> CSV parser -> behavior features -> explainable detection rules -> CSV report
```

## Problem Statement

In a data center, compromised or suspicious hosts often perform reconnaissance before a larger attack. A common signal is port-scanning behavior, where one source communicates with many destination systems or tries many ports in a short period.

Network Bouncer helps analysts answer:

- Which record or source host looks suspicious?
- What behavior caused the alert?
- How severe is the activity?
- What risk score should be assigned?
- Can the result be exported for review?

## Key Features

- Reads UNSW-NB15-style CSV traffic data.
- Supports cleaned UNSW-NB15 files with derived behavior columns.
- Also supports raw network logs when `srcip`, `dstip`, and `dsport` columns are available.
- Computes behavior indicators for destination diversity, port diversity, connection volume, and repeated source-destination behavior.
- Applies explainable rule-based detection.
- Produces classification, severity, risk score, and human-readable reason.
- Exports suspicious activity to a CSV report.
- Includes tests for parser, feature engineering, detection, and reporting modules.

## Project Structure

```text
dell-network-bouncer/
+-- README.md
+-- main.py
+-- requirements.txt
+-- data/
|   +-- cleaned/
|   |   +-- UNSW_NB15_training-set(in).csv
|   |   +-- UNSW_NB15_testing-set(in).csv
|   +-- processed/
|   |   +-- suspicious_activity_report.csv
|   +-- schema/
|       +-- NUSW-NB15_features(in).csv
+-- docs/
|   +-- Problem Statement.pdf
|   +-- Technical_documentaion.pdf
|   +-- user_guide.pdf
|   +-- Architecture_diagram.pdf
|   +-- build_phases.md
+-- models/
|   +-- network_bouncer_model.pkl
+-- src/
|   +-- parser/
|   |   +-- csv_parser.py
|   +-- features/
|   |   +-- host_features.py
|   +-- detection/
|   |   +-- rules.py
|   |   +-- models/
|   +-- reporting/
|   |   +-- report_writer.py
|   +-- dashboard/
+-- tests/
    +-- fixtures/
    +-- test_parser.py
    +-- test_features.py
    +-- test_detection.py
    +-- test_reporting.py
```

## Dataset Notes

The included CSV files are cleaned UNSW-NB15 files. They contain derived behavioral features and labels, but they do not expose actual `srcip`, `dstip`, `sport`, or `dsport` columns.

Important included columns:

- `ct_dst_ltm`: destination-count behavior.
- `ct_src_dport_ltm`: destination-port diversity behavior.
- `ct_dst_sport_ltm`: source-port behavior against destinations.
- `ct_dst_src_ltm`: repeated source-destination relationship count.
- `ct_state_ttl`: state and TTL behavior count.
- `attack_cat`: attack category label.
- `label`: binary label where `0` means normal and `1` means attack.

Because the cleaned files do not include real source IP addresses, Network Bouncer reports cleaned rows as `record-<id>`. If a raw log file with `srcip`, `dstip`, and `dsport` is provided, the same pipeline reports real source IPs.

## Installation

From the project folder:

```powershell
cd "C:\Users\Acer\Desktop\Dell Hackathon\dell-network-bouncer"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks virtual environment activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## How To Run

Run with the default included testing dataset:

```powershell
python main.py
```

Run with an explicit input and output path:

```powershell
python main.py "data/cleaned/UNSW_NB15_testing-set(in).csv" --output data/processed/suspicious_activity_report.csv
```

Tune detection thresholds:

```powershell
python main.py --dst-threshold 50 --port-threshold 30 --connection-threshold 100
```

Include normal rows in the report:

```powershell
python main.py --include-normal
```

Show CLI help:

```powershell
python main.py --help
```

## Output

Default report path:

```text
data/processed/suspicious_activity_report.csv
```

Report columns include:

- `srcip` or generated `record-<id>`.
- `classification`: `Normal`, `Watch`, `Suspicious`, or `High Risk`.
- `severity`: `Low`, `Medium`, or `High`.
- `risk_score`: score from 0 to 100.
- `connection_count`.
- `unique_dstip_count`.
- `unique_dsport_count`.
- `attack_cat` and `label`, when available.
- `reason`: explanation of why the record or host was flagged.

Example reason:

```text
High destination diversity: 59 destinations; High port diversity: 59 destination ports
```

## Detection Approach

Network Bouncer uses explainable rule-based detection as the core method. This was chosen because security analysts and hackathon judges need to understand why a host or row was flagged.

The detector scores activity using:

- Connection volume.
- Destination diversity.
- Destination-port diversity.
- Repeated source-destination behavior.
- Unusual state/TTL patterns.

Higher scores produce stronger classifications:

```text
0      -> Normal
1-34   -> Watch
35-69  -> Suspicious
70-100 -> High Risk
```

## Testing

Install dependencies first, then run:

```powershell
python -m pytest
```

The tests cover:

- CSV loading and validation.
- Raw source-IP feature aggregation.
- Suspicious activity classification.
- CSV report writing.

If `pytest` is not found, run:

```powershell
pip install -r requirements.txt
```

## Team

| Name            | Role        |
| --------------- | ----------- |
| Raj Rathaur     | Team Lead   |
| Anjali Kumari   | Team Member |
| Vanshika Dixit  | Team Member |
| Sonam Sharma    | Team Member |
| Prashant Sharma | Team Member |

## License

This project is developed for educational and hackathon submission purposes.
