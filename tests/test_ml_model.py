import joblib
import pandas as pd

from src.detection.ml_model import add_hybrid_decision, score_with_model


class FakeModel:
    feature_names_in_ = ["dur", "proto", "service", "state"]
    classes_ = [0, 1]

    def predict(self, X):
        return [1 if value > 1 else 0 for value in X["dur"]]

    def predict_proba(self, X):
        return [[0.2, 0.8] if value > 1 else [0.9, 0.1] for value in X["dur"]]


def test_score_with_model_adds_ml_columns(tmp_path):
    model_path = tmp_path / "fake_model.pkl"
    joblib.dump(FakeModel(), model_path)
    df = pd.DataFrame(
        {
            "id": [1, 2],
            "dur": [0.5, 2.0],
            "proto": ["tcp", "udp"],
            "service": ["http", "dns"],
            "state": ["FIN", "INT"],
        }
    )

    scores = score_with_model(df, model_path, encoding_reference=None)

    assert list(scores["ml_prediction"]) == [0, 1]
    assert list(scores["ml_prediction_label"]) == ["Normal", "Attack"]
    assert "ml_attack_probability" in scores.columns


def test_score_with_model_uses_the_configured_probability_threshold(tmp_path):
    model_path = tmp_path / "fake_model.pkl"
    joblib.dump(FakeModel(), model_path)
    df = pd.DataFrame(
        {
            "dur": [2.0],
            "proto": ["tcp"],
            "service": ["http"],
            "state": ["FIN"],
        }
    )

    scores = score_with_model(
        df,
        model_path,
        encoding_reference=None,
        attack_probability_threshold=0.85,
    )

    assert scores.iloc[0]["ml_attack_probability"] == 0.8
    assert scores.iloc[0]["ml_prediction"] == 0


def test_add_hybrid_decision_marks_confirmed_alert():
    results = pd.DataFrame(
        {
            "classification": ["High Risk", "Normal", "Watch"],
            "ml_prediction": [1, 1, 0],
            "ml_prediction_label": ["Attack", "Attack", "Normal"],
        }
    )

    updated = add_hybrid_decision(results)

    assert updated.iloc[0]["hybrid_decision"] == "Confirmed by rules and ML"
    assert updated.iloc[1]["hybrid_decision"] == "ML-only alert"
    assert updated.iloc[2]["hybrid_decision"] == "Rule-based watch"
