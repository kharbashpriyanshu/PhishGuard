# backend/train.py
import os
import json
import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from extract_features import extract_url_features, FEATURE_ORDER

ROOT = os.path.dirname(__file__)
DATA_PATH = os.path.join(ROOT, "..", "data", "sample_urls.csv")  # place your dataset here
OUT_MODEL = os.path.join(ROOT, "model.pkl")
OUT_FEATURES = os.path.join(ROOT, "feature_names.json")
OUT_METRICS_DIR = os.path.join(ROOT, "metrics")
os.makedirs(OUT_METRICS_DIR, exist_ok=True)

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    feats = df["url"].apply(extract_url_features).apply(pd.Series)
    # Ensure column order
    feats = feats[FEATURE_ORDER]
    return feats

def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}. Put CSV with columns: url,label")

    print("Loading dataset:", DATA_PATH)
    df = pd.read_csv(DATA_PATH)
    if not {"url","label"}.issubset(df.columns):
        raise ValueError("Dataset must have columns 'url' and 'label' (1=phishing,0=safe).")

    # Shuffle & small sample during dev if desired
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    X = build_features(df)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training RandomForest...")
    clf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced", n_jobs=-1)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    proba = clf.predict_proba(X_test)[:,1]

    acc = accuracy_score(y_test, preds)
    print(f"Accuracy: {acc:.4f}")
    print("Classification report:")
    print(classification_report(y_test, preds, digits=4))

    # confusion matrix
    cm = confusion_matrix(y_test, preds)
    np.savetxt(os.path.join(OUT_METRICS_DIR, "confusion_matrix.csv"), cm, delimiter=",", fmt='%d')

    # Save model and feature order
    joblib.dump(clf, OUT_MODEL)
    with open(OUT_FEATURES, "w") as f:
        json.dump(FEATURE_ORDER, f)

    # Save metrics summary
    with open(os.path.join(OUT_METRICS_DIR, "summary.txt"), "w") as f:
        f.write(f"Accuracy: {acc:.4f}\n")
        f.write(classification_report(y_test, preds, digits=4))

    print("Saved model to:", OUT_MODEL)
    print("Saved feature order to:", OUT_FEATURES)
    print("Metrics saved to:", OUT_METRICS_DIR)

if __name__ == "__main__":
    main()

