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


def test_time_window_scoring_boosts_scanner_risk():
    """Scanner with microsecond durations should get a 'Rapid scan' reason."""
    df = load_network_csv(Path("tests/fixtures/sample_raw_network_log.csv"))
    features = build_behavior_features(df)
    results = detect_suspicious_activity(
        features,
        DetectionThresholds(destination_count=5, port_count=5, connection_count=5),
    )

    scanner = results[results["srcip"] == "10.0.0.2"].iloc[0]
    normal = results[results["srcip"] == "10.0.0.1"].iloc[0]

    # Scanner has sub-0.1s durations — time-window scoring should apply
    assert "Rapid scan" in scanner["reason"]
    # Normal host has long durations — time-window should NOT apply
    assert "Rapid scan" not in normal["reason"]


def test_time_window_scoring_unsw_record_level():
    """UNSW records with short duration and high diversity get time-window scoring."""
    import pandas as pd

    records = pd.DataFrame({
        "id": [1, 2, 3],
        "ct_dst_ltm": [30, 2, 30],         # unique_dstip_count
        "ct_src_dport_ltm": [30, 1, 30],    # unique_dsport_count
        "ct_dst_sport_ltm": [5, 1, 5],
        "ct_dst_src_ltm": [10, 1, 10],
        "ct_state_ttl": [0, 0, 0],
        "ct_src_ltm": [50, 2, 50],          # connection_count
        "dur": [0.00001, 5.0, 0.00001],     # very fast vs slow
        "rate": [250000, 10, 250000],        # high vs low rate
        "proto": ["tcp", "tcp", "tcp"],
        "service": ["-", "http", "-"],
        "state": ["FIN", "FIN", "REJ"],
        "attack_cat": ["Generic", "Normal", "Generic"],
        "label": [1, 0, 1],
    })

    features = build_behavior_features(records)
    results = detect_suspicious_activity(
        features,
        DetectionThresholds(destination_count=50, port_count=30, connection_count=100),
    )

    fast_scanner = results[results["srcip"] == "record-1"].iloc[0]
    slow_normal = results[results["srcip"] == "record-2"].iloc[0]

    assert "Rapid scan" in fast_scanner["reason"]
    assert "High packet rate" in fast_scanner["reason"]
    assert "Rapid scan" not in slow_normal["reason"]
    assert "High packet rate" not in slow_normal["reason"]
    assert fast_scanner["risk_score"] > slow_normal["risk_score"]
