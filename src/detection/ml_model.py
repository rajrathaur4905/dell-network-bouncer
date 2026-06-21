from __future__ import annotations

import os
import tempfile
import warnings
from pathlib import Path

import pandas as pd


os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "network-bouncer-mpl"))
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")

CATEGORICAL_COLUMNS = ("proto", "service", "state")
DEFAULT_MODEL_PATH = Path("models/network_bouncer_model.pkl")
DEFAULT_ENCODING_REFERENCE = Path("data/cleaned/UNSW_NB15_training-set(in).csv")
DEFAULT_ATTACK_PROBABILITY_THRESHOLD = 0.65


class MlModelError(RuntimeError):
    """Raised when ML scoring cannot be completed."""


def score_with_model(
    df: pd.DataFrame,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    encoding_reference: str | Path | None = DEFAULT_ENCODING_REFERENCE,
    attack_probability_threshold: float = DEFAULT_ATTACK_PROBABILITY_THRESHOLD,
) -> pd.DataFrame:
    if not 0 <= attack_probability_threshold <= 1:
        raise MlModelError("ML attack-probability threshold must be between 0 and 1")

    model = _load_model(model_path)
    feature_names = _get_feature_names(model)
    category_mappings = _load_category_mappings(encoding_reference)
    model_input = _prepare_model_input(df, feature_names, category_mappings)

    scores = pd.DataFrame(index=df.index)
    scores["record_id"] = df["id"] if "id" in df.columns else df.index + 1

    if hasattr(model, "predict_proba"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                probabilities = model.predict_proba(model_input)
                class_index = _attack_class_index(model)
                probability_frame = pd.DataFrame(probabilities)
                attack_probabilities = probability_frame.iloc[:, class_index]
                scores["ml_attack_probability"] = attack_probabilities.round(4).to_numpy()
                # Keep runtime decisions aligned with the threshold used to evaluate
                # this model in the training notebook.
                predictions = (attack_probabilities > attack_probability_threshold).astype(int)
            except Exception as exc:
                raise MlModelError(f"model probability scoring failed: {exc}") from exc
    else:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                predictions = model.predict(model_input)
            except Exception as exc:
                raise MlModelError(f"model prediction failed: {exc}") from exc

    scores["ml_prediction"] = predictions
    scores["ml_prediction_label"] = scores["ml_prediction"].map({0: "Normal", 1: "Attack"}).fillna(
        scores["ml_prediction"].astype(str)
    )
    scores["ml_model_used"] = Path(model_path).name

    return scores


def add_hybrid_decision(results: pd.DataFrame) -> pd.DataFrame:
    if "ml_prediction" not in results.columns:
        return results

    updated = results.copy()
    decisions: list[str] = []
    for row in updated.to_dict("records"):
        rule_class = str(row.get("classification", "Normal"))
        ml_prediction = row.get("ml_prediction")
        ml_attack = str(ml_prediction) == "1" or str(row.get("ml_prediction_label")) == "Attack"

        if rule_class in {"High Risk", "Suspicious"} and ml_attack:
            decisions.append("Confirmed by rules and ML")
        elif rule_class in {"High Risk", "Suspicious"}:
            decisions.append("Rule-based alert")
        elif rule_class == "Watch" and ml_attack:
            decisions.append("Rule-based watch with ML support")
        elif rule_class == "Watch":
            decisions.append("Rule-based watch")
        elif ml_attack:
            decisions.append("ML-only alert")
        else:
            decisions.append("No alert")

    updated["hybrid_decision"] = decisions
    return updated


def _load_model(model_path: str | Path):
    path = Path(model_path)
    if not path.exists():
        raise MlModelError(f"model file not found: {path}")

    try:
        import joblib
    except ImportError as exc:
        raise MlModelError("joblib is required to load the ML model") from exc

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return joblib.load(path)
        except ImportError as exc:
            raise MlModelError(
                f"missing model dependency: {exc.name}. Install dependencies from requirements.txt."
            ) from exc
        except Exception as exc:
            raise MlModelError(f"could not load model: {exc}") from exc


def _get_feature_names(model) -> list[str]:
    feature_names = getattr(model, "feature_names_in_", None)
    if feature_names is None:
        raise MlModelError("model does not expose feature_names_in_; cannot prepare safe input")
    return [str(feature).strip().lower() for feature in feature_names]


def _load_category_mappings(
    encoding_reference: str | Path | None,
) -> dict[str, dict[str, int]]:
    if encoding_reference is None:
        return {}

    path = Path(encoding_reference)
    if not path.exists():
        raise MlModelError(f"categorical encoding reference file not found: {path}")

    try:
        reference = pd.read_csv(path)
    except Exception as exc:
        raise MlModelError(f"could not read encoding reference CSV: {exc}") from exc

    reference.columns = [str(column).strip().lower() for column in reference.columns]
    mappings: dict[str, dict[str, int]] = {}
    for column in CATEGORICAL_COLUMNS:
        if column in reference.columns:
            categories = sorted(reference[column].fillna("missing").astype(str).unique())
            mappings[column] = {value: index for index, value in enumerate(categories)}
    return mappings


def _prepare_model_input(
    df: pd.DataFrame,
    feature_names: list[str],
    category_mappings: dict[str, dict[str, int]],
) -> pd.DataFrame:
    missing = [column for column in feature_names if column not in df.columns]
    if missing:
        raise MlModelError(
            "input CSV is missing ML model columns: " + ", ".join(missing)
        )

    model_input = df.loc[:, feature_names].copy()
    for column in CATEGORICAL_COLUMNS:
        if column in model_input.columns:
            mapping = category_mappings.get(column)
            if mapping is None:
                categories = sorted(model_input[column].fillna("missing").astype(str).unique())
                mapping = {value: index for index, value in enumerate(categories)}
            model_input[column] = model_input[column].fillna("missing").astype(str).map(mapping).fillna(-1)

    for column in model_input.columns:
        model_input[column] = pd.to_numeric(model_input[column], errors="coerce").fillna(0)

    return model_input


def _attack_class_index(model) -> int:
    classes = list(getattr(model, "classes_", [0, 1]))
    if 1 in classes:
        return classes.index(1)
    return len(classes) - 1
