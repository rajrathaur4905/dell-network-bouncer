"""Small, testable helpers for the Streamlit dashboard."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


NORMAL_LABELS = {"normal"}


@dataclass(frozen=True)
class DashboardSummary:
    suspicious_df: pd.DataFrame
    total_alerts: int
    high_risk_count: int
    suspicious_count: int
    watch_count: int


def normalize_report(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize report fields used by the dashboard without mutating input."""
    normalized = df.copy()
    if "classification" in normalized.columns:
        normalized["classification"] = normalized["classification"].astype(str).str.strip()
    if "severity" in normalized.columns:
        normalized["severity_upper"] = normalized["severity"].astype(str).str.strip().str.upper()
    return normalized


def apply_severity_filter(df: pd.DataFrame, severities: list[str]) -> pd.DataFrame:
    """Filter report rows by selected severities.

    An empty severity list intentionally returns no rows, matching the UI when
    every severity option is deselected.
    """
    if "severity_upper" not in df.columns:
        return df

    selected = [severity.upper() for severity in severities]
    return df[df["severity_upper"].isin(selected)]


def summarize_report(df: pd.DataFrame) -> DashboardSummary:
    """Return alert-focused dashboard counts and rows."""
    classification = df["classification"].astype(str).str.strip().str.lower()
    suspicious_df = df[~classification.isin(NORMAL_LABELS)]

    return DashboardSummary(
        suspicious_df=suspicious_df,
        total_alerts=len(suspicious_df),
        high_risk_count=int((classification == "high risk").sum()),
        suspicious_count=int((classification == "suspicious").sum()),
        watch_count=int((classification == "watch").sum()),
    )
