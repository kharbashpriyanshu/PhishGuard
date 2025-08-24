import joblib
import sys
from features import extract_features
import pandas as pd

MODEL_PATH = "phishing_model.pkl"

def predict_url(url: str):
    # Load model
    model = joblib.load(MODEL_PATH)

    # Extract features
    feats = extract_features(url)

    # Keep only numeric values (drop 'extracted' dict etc.)
    clean_feats = {k: v for k, v in feats.items() if isinstance(v, (int, float))}

    # Convert to DataFrame
    X = pd.DataFrame([clean_feats]).fillna(0)

    # Predict
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0]

    label = "Phishing" if pred == 1 else "Legitimate"
    confidence = round(max(proba) * 100, 2)

    return label, confidence


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    label, conf = predict_url(url)
    print(f"[RESULT] URL: {url}")
    print(f"[RESULT] Prediction: {label} ({conf}% confidence)")
