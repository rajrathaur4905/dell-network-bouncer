from pathlib import Path

from src.features.host_features import build_behavior_features
from src.parser.csv_parser import load_network_csv


def test_build_behavior_features_groups_raw_logs_by_source_ip():
    df = load_network_csv(Path("tests/fixtures/sample_raw_network_log.csv"))
    features = build_behavior_features(df)
    scanner = features[features["srcip"] == "10.0.0.2"].iloc[0]

    assert scanner["connection_count"] == 6
    assert scanner["unique_dstip_count"] == 6
    assert scanner["unique_dsport_count"] == 6
    assert scanner["failed_or_rejected_count"] == 6
