# Network Bouncer

Network Bouncer is a Python cybersecurity analytics tool for detecting suspicious scan-like behavior in network traffic. It was built for the Dell hackathon use case of finding hosts or records that contact many destinations, try many ports, or show abnormal connection patterns.

Pipeline:

```text
CSV input -> CSV parser -> behavior features -> rule-based detection -> optional ML scoring -> CSV report -> optional dashboard
```

## What It Does

- Reads cleaned UNSW-NB15-style CSV traffic data.
- Also supports raw network logs when `srcip`, `dstip`, and `dsport` are available.
- Computes behavior indicators for destination diversity, port diversity, connection volume, and repeated source-destination behavior.
- Applies explainable rule-based detection.
- Optionally adds ML attack predictions from the trained model in `models/network_bouncer_model.pkl`.
- Writes a suspicious activity CSV report.
- Provides a Streamlit dashboard for report review.
- Includes tests for parsing, feature engineering, detection, ML scoring, reporting, and dashboard report processing.

## Current Project Structure

```text
dell-network-bouncer/
+-- README.md
+-- main.py
+-- requirements.txt
+-- .gitignore
+-- data/
|   +-- cleaned/
|   |   +-- UNSW_NB15_training-set(in).csv
|   |   +-- UNSW_NB15_testing-set(in).csv
|   +-- processed/              # generated reports, ignored by git
|   +-- schema/
|       +-- NUSW-NB15_features(in).csv
|
+-- docs/                       # project PDFs and documentation assets
+-- models/
|   +-- network_bouncer_model.pkl
+-- notebooks/
|   +-- Detecting_suspicious_port_scanning.ipynb
|
+-- screenshots/
|   +-- dashboard_img_1.png
|   +-- dashboard_img_2.png
|   +-- dashboard_img_3.png
|   +-- dashboard_img_4.png
|
+-- src/
|   +-- parser/
|   |   +-- csv_parser.py
|   +-- features/
|   |   +-- host_features.py
|   +-- detection/
|   |   +-- rules.py
|   |   +-- ml_model.py
|   +-- reporting/
|   |   +-- report_writer.py
|   +-- dashboard/
|       +-- __init__.py
|       +-- dashboard.py
|       +-- report_processing.py
|
+-- tests/
    +-- fixtures/
    +-- test_parser.py
    +-- test_features.py
    +-- test_detection.py
    +-- test_ml_model.py
    +-- test_reporting.py
    +-- test_dashboard.py
```

## Important Locations

- `models/network_bouncer_model.pkl` is the canonical trained ML model location.
- `notebooks/Detecting_suspicious_port_scanning.ipynb` contains the model training/evaluation notebook.
- `src/dashboard/dashboard.py` is the Streamlit UI.
- `src/dashboard/report_processing.py` contains dashboard filtering and summary logic that is covered by tests.
- `data/processed/` is for generated reports and is ignored by git.
- `src/detection/models/` should not contain duplicate model files; local `.pkl` or `.joblib` copies there are ignored.

## Dataset Notes

The included CSV files are cleaned UNSW-NB15 files. They contain derived behavioral features and labels, but they do not expose real `srcip`, `dstip`, `sport`, or `dsport` columns.

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

The currently pinned dependency versions are:

```text
pandas==2.3.3
numpy==2.2.6
scikit-learn==1.6.1
xgboost==3.2.0
lightgbm==4.6.0
catboost==1.2.10
imbalanced-learn==0.14.2
joblib==1.5.3
streamlit==1.58.0
matplotlib==3.10.9
pytest==9.1.1
```

## How To Run The CLI

Run with the default included testing dataset:

```powershell
python main.py
```

Run with an explicit input and output path:

```powershell
python main.py "data/cleaned/UNSW_NB15_testing-set(in).csv" --output data/processed/suspicious_activity_report.csv
```

Tune rule-based thresholds:

```powershell
python main.py --dst-threshold 50 --port-threshold 30 --connection-threshold 100
```

Include normal rows in the report:

```powershell
python main.py --include-normal
```

Run hybrid rule-based and ML detection:

```powershell
python main.py --use-ml
```

Run hybrid detection with explicit model and encoding-reference paths:

```powershell
python main.py --use-ml --model-path models/network_bouncer_model.pkl --encoding-reference "data/cleaned/UNSW_NB15_training-set(in).csv"
```

The ML prediction threshold defaults to `0.65`, matching the evaluation threshold used in the training notebook. To deliberately tune it for a different operating environment, pass a value from 0 to 1:

```powershell
python main.py --use-ml --ml-threshold 0.65
```

Show CLI help:

```powershell
python main.py --help
```

## Expected CLI Output

Default report path:

```text
data/processed/suspicious_activity_report.csv
```

Console output summarizes suspicious activity and points to the generated report. Report columns can include:

- `srcip` or generated `record-<id>`.
- `classification`: `Normal`, `Watch`, `Suspicious`, or `High Risk`.
- `severity`: `Low`, `Medium`, or `High`.
- `risk_score`: score from 0 to 100.
- `connection_count`.
- `unique_dstip_count`.
- `unique_dsport_count`.
- `attack_cat` and `label`, when available.
- `reason`: explanation of why the record or host was flagged.
- `ml_prediction`, `ml_prediction_label`, `ml_attack_probability`, and `hybrid_decision` when `--use-ml` is enabled.

## Dashboard

After generating a report, launch the dashboard:

```powershell
streamlit run src/dashboard/dashboard.py
```

Then upload a CSV report such as:

```text
data/processed/suspicious_activity_report.csv
```

Dashboard behavior:

- Severity filters are `HIGH`, `MEDIUM`, and `LOW`.
- If every severity is deselected, no rows are shown.
- KPI cards focus on alert classes: total alerts, high risk, suspicious, and watch.
- ML insight widgets appear only when ML columns are present in the uploaded report.

## Detection Approach

Network Bouncer uses a hybrid detection strategy. Rule-based detection is the primary explainable layer, and the trained ML model supplies an additional prediction and attack probability when `--use-ml` is enabled.

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

### ML Scoring

The included `network_bouncer_model.pkl` is a stacking classifier built with XGBoost, LightGBM, CatBoost, and logistic regression. It expects 42 UNSW-NB15 features, including `dur`, `proto`, `service`, `state`, traffic statistics, and derived connection-count fields.

ML predictions use the model's attack probability and the configured threshold, default `0.65`, rather than the classifier's implicit default threshold.

For consistent ML scoring, categorical values are encoded using the included UNSW training CSV by default:

```text
data/cleaned/UNSW_NB15_training-set(in).csv
```

The model is intended for compatible cleaned UNSW-NB15 inputs. Raw logs that only contain `srcip`, `dstip`, and `dsport` can still use rule-based detection, but do not contain enough columns for this ML model.

## Testing

Install dependencies first, then run:

```powershell
python -m pytest
```

Current tests cover:

- CSV loading and validation.
- Raw source-IP feature aggregation.
- Suspicious activity classification.
- Optional ML model scoring and hybrid decisions.
- CSV report writing.
- Dashboard report filtering and summary behavior.

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
