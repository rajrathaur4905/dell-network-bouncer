import pandas as pd
from streamlit.testing.v1 import AppTest

from src.dashboard.report_processing import (
    apply_severity_filter,
    normalize_report,
    summarize_report,
)


DASHBOARD_PATH = "src/dashboard/dashboard.py"


def _dashboard() -> AppTest:
    return AppTest.from_file(DASHBOARD_PATH)


def test_dashboard_prompts_for_a_report_before_rendering_analysis():
    app = _dashboard().run()

    assert not app.exception
    assert len(app.get("file_uploader")) == 1
    assert any("Upload your suspicious_activity_report.csv" in alert.value for alert in app.warning)


def test_dashboard_summary_counts_alert_classes_without_counting_normal_as_alerts():
    report = normalize_report(pd.DataFrame(
        [
            {
                "srcip": "192.168.1.10",
                "classification": "High Risk",
                "severity": "High",
                "risk_score": 85,
                "connection_count": 150,
                "unique_dstip_count": 80,
                "unique_dsport_count": 60,
                "reason": "High port diversity",
            },
            {
                "srcip": "192.168.1.20",
                "classification": "Normal",
                "severity": "Low",
                "risk_score": 0,
                "connection_count": 1,
                "unique_dstip_count": 1,
                "unique_dsport_count": 1,
                "reason": "No threshold crossed",
            },
        ]
    ))

    summary = summarize_report(report)

    assert summary.total_alerts == 1
    assert summary.high_risk_count == 1
    assert summary.suspicious_count == 0
    assert summary.watch_count == 0
    assert summary.suspicious_df.iloc[0]["srcip"] == "192.168.1.10"


def test_dashboard_processing_preserves_optional_ml_columns_when_available():
    report = normalize_report(pd.DataFrame(
        [
            {
                "srcip": "192.168.1.10",
                "classification": "Suspicious",
                "severity": "Medium",
                "risk_score": 60,
                "connection_count": 90,
                "unique_dstip_count": 50,
                "unique_dsport_count": 35,
                "ml_prediction_label": "Attack",
                "ml_attack_probability": 0.82,
                "reason": "High port diversity",
            }
        ]
    ))

    summary = summarize_report(report)

    assert "ml_attack_probability" in summary.suspicious_df.columns
    assert summary.suspicious_df.iloc[0]["ml_prediction_label"] == "Attack"


def test_dashboard_filter_returns_no_rows_when_every_severity_is_deselected():
    report = normalize_report(pd.DataFrame(
        [
            {
                "srcip": "192.168.1.10",
                "classification": "High Risk",
                "severity": "High",
                "risk_score": 85,
                "connection_count": 150,
                "unique_dstip_count": 80,
                "unique_dsport_count": 60,
                "reason": "High port diversity",
            }
        ]
    ))

    filtered = apply_severity_filter(report, [])
    summary = summarize_report(filtered)

    assert filtered.empty
    assert summary.total_alerts == 0
