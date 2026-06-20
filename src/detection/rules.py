from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class DetectionThresholds:
    destination_count: int = 50
    port_count: int = 30
    connection_count: int = 100


def detect_suspicious_activity(
    features: pd.DataFrame, thresholds: DetectionThresholds
) -> pd.DataFrame:
    results = features.copy()
    classifications: list[str] = []
    severities: list[str] = []
    risk_scores: list[int] = []
    reasons: list[str] = []

    for row in results.to_dict("records"):
        risk_score, reason_parts = _score_row(row, thresholds)
        classification, severity = _classify(risk_score, reason_parts)
        classifications.append(classification)
        severities.append(severity)
        risk_scores.append(risk_score)
        reasons.append("; ".join(reason_parts) if reason_parts else "No threshold crossed")

    results["classification"] = classifications
    results["severity"] = severities
    results["risk_score"] = risk_scores
    results["reason"] = reasons
    return results.sort_values(
        by=["risk_score", "unique_dstip_count", "unique_dsport_count", "connection_count"],
        ascending=[False, False, False, False],
    )


def _score_row(row: dict, thresholds: DetectionThresholds) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    connection_count = _number(row.get("connection_count"))
    dst_count = _number(row.get("unique_dstip_count"))
    port_count = _number(row.get("unique_dsport_count"))
    relationship_count = _number(row.get("dst_src_relationship_count"))
    state_ttl_count = _number(row.get("state_ttl_count"))

    if connection_count >= thresholds.connection_count:
        score += 35
        reasons.append(f"High connection volume: {connection_count:g} connections")
    elif connection_count >= thresholds.connection_count * 0.5:
        score += 15
        reasons.append(f"Elevated connection volume: {connection_count:g} connections")

    if dst_count >= thresholds.destination_count:
        score += 30
        reasons.append(f"High destination diversity: {dst_count:g} destinations")
    elif dst_count >= thresholds.destination_count * 0.5:
        score += 12
        reasons.append(f"Elevated destination diversity: {dst_count:g} destinations")

    if port_count >= thresholds.port_count:
        score += 30
        reasons.append(f"High port diversity: {port_count:g} destination ports")
    elif port_count >= thresholds.port_count * 0.5:
        score += 12
        reasons.append(f"Elevated port diversity: {port_count:g} destination ports")

    if relationship_count >= max(10, thresholds.destination_count * 0.5):
        score += 10
        reasons.append(f"Repeated source-destination behavior: {relationship_count:g} links")

    if state_ttl_count >= 5:
        score += 8
        reasons.append(f"Unusual state/TTL pattern count: {state_ttl_count:g}")

    return min(score, 100), reasons


def _classify(score: int, reasons: list[str]) -> tuple[str, str]:
    if score >= 70:
        return "High Risk", "High"
    if score >= 35 or len(reasons) >= 2:
        return "Suspicious", "Medium"
    if score > 0:
        return "Watch", "Low"
    return "Normal", "Low"


def _number(value: object) -> float:
    try:
        if pd.isna(value):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0
