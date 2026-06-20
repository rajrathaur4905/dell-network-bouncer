import pandas as pd

from src.reporting.report_writer import write_report


def test_write_report_creates_csv(tmp_path):
    output = tmp_path / "report.csv"
    results = pd.DataFrame(
        [
            {
                "srcip": "10.0.0.2",
                "classification": "High Risk",
                "severity": "High",
                "risk_score": 95,
                "connection_count": 6,
                "unique_dstip_count": 6,
                "unique_dsport_count": 6,
                "reason": "High port diversity",
            }
        ]
    )

    write_report(results, output)

    saved = pd.read_csv(output)
    assert saved.iloc[0]["srcip"] == "10.0.0.2"
    assert saved.iloc[0]["classification"] == "High Risk"
