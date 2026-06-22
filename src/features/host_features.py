from __future__ import annotations

import pandas as pd


UNSW_SCAN_COLUMNS = [
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_state_ttl",
    "ct_srv_src",
    "ct_src_ltm",
    "ct_srv_dst",
]


def build_behavior_features(df: pd.DataFrame) -> pd.DataFrame:
    if {"srcip", "dstip", "dsport"}.issubset(df.columns):
        return _build_raw_host_features(df)
    return _build_unsw_record_features(df)


def _build_raw_host_features(df: pd.DataFrame) -> pd.DataFrame:
    aggregations: dict[str, tuple[str, str]] = {
        "connection_count": ("srcip", "size"),
        "unique_dstip_count": ("dstip", "nunique"),
        "unique_dsport_count": ("dsport", "nunique"),
    }

    if "proto" in df.columns:
        aggregations["unique_proto_count"] = ("proto", "nunique")
    if "service" in df.columns:
        aggregations["unique_service_count"] = ("service", "nunique")

    features = df.groupby("srcip", dropna=False).agg(**aggregations).reset_index()

    if "state" in df.columns:
        failed_states = {"rej", "rst", "int", "no", "eco"}
        failed = (
            df.assign(_failed_state=df["state"].astype(str).str.lower().isin(failed_states))
            .groupby("srcip")["_failed_state"]
            .sum()
            .reset_index(name="failed_or_rejected_count")
        )
        features = features.merge(failed, on="srcip", how="left")
    else:
        features["failed_or_rejected_count"] = 0

    # Time-window features for raw host aggregation
    if "dur" in df.columns:
        dur_agg = df.groupby("srcip")["dur"].agg(
            mean_duration="mean", min_duration="min"
        ).reset_index()
        features = features.merge(dur_agg, on="srcip", how="left")
        short_dur = (
            df.assign(_is_short=(pd.to_numeric(df["dur"], errors="coerce").fillna(0) < 0.1))
            .groupby("srcip")["_is_short"]
            .mean()
            .reset_index(name="pct_short_duration")
        )
        features = features.merge(short_dur, on="srcip", how="left")
    else:
        features["mean_duration"] = float("nan")
        features["min_duration"] = float("nan")
        features["pct_short_duration"] = float("nan")

    if "rate" in df.columns:
        rate_agg = df.groupby("srcip")["rate"].agg(
            mean_rate="mean", max_rate="max"
        ).reset_index()
        features = features.merge(rate_agg, on="srcip", how="left")
    else:
        features["mean_rate"] = float("nan")
        features["max_rate"] = float("nan")

    features["source_type"] = "raw_host"
    return features


def _build_unsw_record_features(df: pd.DataFrame) -> pd.DataFrame:
    features = pd.DataFrame()
    features["record_id"] = df["id"] if "id" in df.columns else df.index + 1
    features["srcip"] = "record-" + features["record_id"].astype(str)
    features["connection_count"] = df.get("ct_src_ltm", pd.Series(1, index=df.index)).fillna(1)
    features["unique_dstip_count"] = df["ct_dst_ltm"].fillna(0)
    features["unique_dsport_count"] = df["ct_src_dport_ltm"].fillna(0)
    features["dst_src_relationship_count"] = df["ct_dst_src_ltm"].fillna(0)
    features["dst_sport_count"] = df["ct_dst_sport_ltm"].fillna(0)
    features["state_ttl_count"] = df.get("ct_state_ttl", pd.Series(0, index=df.index)).fillna(0)
    features["service_source_count"] = df.get("ct_srv_src", pd.Series(0, index=df.index)).fillna(0)
    features["service_destination_count"] = df.get("ct_srv_dst", pd.Series(0, index=df.index)).fillna(0)
    features["proto"] = df["proto"] if "proto" in df.columns else ""
    features["service"] = df["service"] if "service" in df.columns else ""
    features["state"] = df["state"] if "state" in df.columns else ""
    features["attack_cat"] = df["attack_cat"] if "attack_cat" in df.columns else ""
    features["label"] = df["label"] if "label" in df.columns else pd.NA

    # Time-window features for UNSW record-level analysis
    dur_series = pd.to_numeric(df.get("dur", pd.Series(float("nan"), index=df.index)), errors="coerce").fillna(0)
    features["dur"] = dur_series
    features["is_short_duration"] = (dur_series < 0.1).astype(int)
    features["rate"] = pd.to_numeric(df.get("rate", pd.Series(0, index=df.index)), errors="coerce").fillna(0)
    # Estimate connections-per-second from rate; guard against missing rate
    features["connections_per_second"] = features["rate"]

    features["source_type"] = "unsw_record"
    return features
