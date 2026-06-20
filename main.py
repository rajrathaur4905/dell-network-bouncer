from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.detection.ml_model import (
    DEFAULT_ENCODING_REFERENCE,
    DEFAULT_MODEL_PATH,
    MlModelError,
    add_hybrid_decision,
    score_with_model,
)
from src.detection.rules import DetectionThresholds, detect_suspicious_activity
from src.features.host_features import build_behavior_features
from src.parser.csv_parser import CsvValidationError, load_network_csv
from src.reporting.report_writer import print_console_summary, write_report


DEFAULT_INPUT = Path("data/cleaned/UNSW_NB15_testing-set(in).csv")
DEFAULT_OUTPUT = Path("data/processed/suspicious_activity_report.csv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Network Bouncer detects suspicious scan-like network behavior "
            "from raw network logs or cleaned UNSW-NB15 CSV files."
        )
    )
    parser.add_argument(
        "input_csv",
        nargs="?",
        default=str(DEFAULT_INPUT),
        help=f"Input CSV path. Defaults to {DEFAULT_INPUT}.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output report CSV path. Defaults to {DEFAULT_OUTPUT}.",
    )
    parser.add_argument(
        "--dst-threshold",
        type=int,
        default=50,
        help="Destination diversity threshold for suspicious behavior.",
    )
    parser.add_argument(
        "--port-threshold",
        type=int,
        default=30,
        help="Destination-port diversity threshold for suspicious behavior.",
    )
    parser.add_argument(
        "--connection-threshold",
        type=int,
        default=100,
        help="Connection-volume threshold for suspicious behavior.",
    )
    parser.add_argument(
        "--include-normal",
        action="store_true",
        help="Include normal records or hosts in the output report.",
    )
    parser.add_argument(
        "--use-ml",
        action="store_true",
        help="Add predictions from the trained ML model to the report.",
    )
    parser.add_argument(
        "--model-path",
        default=str(DEFAULT_MODEL_PATH),
        help=f"Path to the trained ML model. Defaults to {DEFAULT_MODEL_PATH}.",
    )
    parser.add_argument(
        "--encoding-reference",
        default=str(DEFAULT_ENCODING_REFERENCE),
        help=(
            "Training CSV used to recreate categorical feature encodings for ML scoring. "
            f"Defaults to {DEFAULT_ENCODING_REFERENCE}."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input_csv)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        print("Place a CSV in data/cleaned or pass the path explicitly.", file=sys.stderr)
        return 2

    thresholds = DetectionThresholds(
        destination_count=args.dst_threshold,
        port_count=args.port_threshold,
        connection_count=args.connection_threshold,
    )

    try:
        rows = load_network_csv(input_path)
        features = build_behavior_features(rows)
        results = detect_suspicious_activity(features, thresholds)
        if args.use_ml:
            ml_scores = score_with_model(rows, args.model_path, args.encoding_reference)
            if "record_id" in results.columns:
                results = results.merge(ml_scores, on="record_id", how="left")
            else:
                results = results.join(ml_scores.drop(columns=["record_id"], errors="ignore"))
            results = add_hybrid_decision(results)
        if not args.include_normal:
            include_alerts = results["classification"] != "Normal"
            if args.use_ml:
                include_alerts = include_alerts | (results["ml_prediction"] == 1)
            results = results[include_alerts].copy()
        write_report(results, output_path)
        print_console_summary(results, output_path)
    except CsvValidationError as exc:
        print(f"CSV validation error: {exc}", file=sys.stderr)
        return 2
    except MlModelError as exc:
        print(f"ML model error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
