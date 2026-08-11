import os
import glob
import json
from typing import Dict, Any

import pandas as pd
import joblib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.alert_parser import parse_raw_alert

MODELS_DIR = os.environ.get("MODELS_DIR", "/app/models")
ENCODER_DIR = os.environ.get("ENCODER_DIR", "/app/encoder")
ENCODER_PATH = os.path.join(ENCODER_DIR, "onehot_encoder.joblib")

DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "xgboost")

# Must exactly match notebook 02 (feature engineering) / notebook 03 (encoding)
CATEGORICAL_COLUMNS = ["priority", "rule", "mitre_tactic", "user_name", "image_repo"]
NUMERIC_COLUMNS = ["hour", "cmdline_length", "suspicious_cmd_flag", "has_process_detail", "has_file_event"]
FEATURE_COLUMNS = CATEGORICAL_COLUMNS + NUMERIC_COLUMNS

app = FastAPI(
    title="Falco APT Alert Classifier",
    description="Classifies a Falco/Kubernetes runtime alert as attack or normal, "
                "using the top 3 model/strategy combinations from model comparison.",
    version="1.0.0",
)

models = {}
encoder = None


@app.on_event("startup")
def load_artifacts():
    global models, encoder

    # Load the encoder from its own folder
    encoder = joblib.load(ENCODER_PATH)

    # Load every model file found in the models folder
    model_files = glob.glob(os.path.join(MODELS_DIR, "*.joblib"))
    for file_path in model_files:
        file_name = os.path.basename(file_path)          # e.g. "xgboost.joblib"
        model_name = file_name.replace(".joblib", "")      # e.g. "xgboost"
        models[model_name] = joblib.load(file_path)

    print("Loaded models:", list(models.keys()))


class AlertFeatures(BaseModel):
    priority: str = Field(..., examples=["Warning"])
    rule: str = Field(..., examples=["Launch Privileged Container"])
    mitre_tactic: str = Field(..., examples=["none"])
    user_name: str = Field(..., examples=["root"])
    image_repo: str = Field(..., examples=["nginx"])
    hour: int = Field(..., ge=0, le=23, examples=[14])
    cmdline_length: int = Field(..., ge=0, examples=[42])
    suspicious_cmd_flag: int = Field(..., ge=0, le=1, examples=[0])
    has_process_detail: int = Field(..., ge=0, le=1, examples=[1])
    has_file_event: int = Field(..., ge=0, le=1, examples=[0])


class PredictRequest(BaseModel):
    alert: AlertFeatures
    model: str = Field(default=None, description="Which model to use. Defaults to the best model.")


class PredictionResult(BaseModel):
    model: str
    prediction: str
    attack_probability: float
    confidence: str
    confidence_level: str


def get_confidence_level(confidence):
    if confidence >= 0.90:
        return "high"
    elif confidence >= 0.70:
        return "medium"
    else:
        return "low"



def encode_features(alert_df):
    # Turn the categorical columns into 0/1 columns, using the encoder
    # that was already fitted during training (we only call .transform here,
    # never .fit, so the columns line up exactly like they did in training)
    encoded_array = encoder.transform(alert_df[CATEGORICAL_COLUMNS])
    encoded_df = pd.DataFrame(
        encoded_array,
        columns=encoder.get_feature_names_out(CATEGORICAL_COLUMNS),
    )

    numeric_df = alert_df[NUMERIC_COLUMNS].reset_index(drop=True)
    encoded_df = encoded_df.reset_index(drop=True)

    # Put the encoded categorical columns and the numeric columns side by side
    full_row = pd.concat([encoded_df, numeric_df], axis=1)
    return full_row


def run_model(model_name, encoded_row):
    if model_name not in models:
        raise HTTPException(status_code=400, detail=f"Unknown model '{model_name}'. Available: {list(models.keys())}")

    model = models[model_name]
    prediction = model.predict(encoded_row)[0]
    attack_probability = model.predict_proba(encoded_row)[0][1]  # probability of "attack"
    
    confidence = max(attack_probability, 1 - attack_probability)
    confidence_percent = round(float(confidence) * 100, 2)

    return PredictionResult(
        model=model_name,
        prediction="attack" if prediction == 1 else "normal",
        attack_probability=round(float(attack_probability), 4),
        confidence=f"{confidence_percent}%",
        confidence_level=get_confidence_level(confidence),
    )


@app.get("/")
def root():
    return {"message": "Welcome to the Falco APT Alert Classifier API"}

@app.get("/health")
def health():
    return {"status": "ok", "models_loaded": list(models.keys()), "encoder_loaded": encoder is not None}


@app.get("/models")
def list_models():
    return {"available_models": list(models.keys()), "default_model": DEFAULT_MODEL}


@app.post("/predict", response_model=PredictionResult)
def predict(request: PredictRequest):
    model_name = request.model or DEFAULT_MODEL
    alert_df = pd.DataFrame([request.alert.model_dump()])[FEATURE_COLUMNS]
    encoded_row = encode_features(alert_df)
    # print("encoded_row:", json.dumps(encoded_row.to_dict(), indent=2))
    return run_model(model_name, encoded_row)


@app.post("/predict/compare", response_model=list[PredictionResult])
def predict_compare(alert: AlertFeatures):
    alert_df = pd.DataFrame([alert.model_dump()])[FEATURE_COLUMNS]
    encoded_row = encode_features(alert_df)
    # print("encoded_row:", json.dumps(encoded_row.to_dict(), indent=2))
    results = []
    for model_name in models.keys():
        results.append(run_model(model_name, encoded_row))
    return results

@app.post("/predict/raw", response_model=PredictionResult)
def predict_raw(raw_alert: Dict[str, Any], model: str = None):
    """Send a REAL, unmodified Falco alert. Features are derived internally
    by alert_parser.parse_raw_alert(). Optionally pick a model with ?model=..."""
    parsed = parse_raw_alert(raw_alert)
    print("parsed raw alert:", json.dumps(parsed, indent=2))
    alert_df = pd.DataFrame([parsed])[FEATURE_COLUMNS]
    encoded_row = encode_features(alert_df)
    # print("encoded_row:", json.dumps(encoded_row.to_dict(), indent=2))
    model_name = model or DEFAULT_MODEL
    return run_model(model_name, encoded_row)


@app.post("/predict/raw/compare", response_model=list[PredictionResult])
def predict_raw_compare(raw_alert: Dict[str, Any]):
    parsed = parse_raw_alert(raw_alert)
    print("parsed raw alert:", json.dumps(parsed, indent=2))
    alert_df = pd.DataFrame([parsed])[FEATURE_COLUMNS]
    encoded_row = encode_features(alert_df)
    # print("encoded_row:", json.dumps(encoded_row.to_dict(), indent=2))
    results = []
    for model_name in models.keys():
        results.append(run_model(model_name, encoded_row))
    return results