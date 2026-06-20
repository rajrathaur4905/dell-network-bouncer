from pathlib import Path

from src.detection.rules import DetectionThresholds, detect_suspicious_activity
from src.features.host_features import build_behavior_features
from src.parser.csv_parser import load_network_csv


def test_detect_suspicious_activity_flags_scan_like_host():
    df = load_network_csv(Path("tests/fixtures/sample_raw_network_log.csv"))
    features = build_behavior_features(df)
    results = detect_suspicious_activity(
        features,
        DetectionThresholds(destination_count=5, port_count=5, connection_count=5),
    )

    scanner = results[results["srcip"] == "10.0.0.2"].iloc[0]
    normal = results[results["srcip"] == "10.0.0.1"].iloc[0]

    assert scanner["classification"] == "High Risk"
    assert scanner["risk_score"] >= normal["risk_score"]
    assert "High destination diversity" in scanner["reason"]
