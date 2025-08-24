# evaluate.py
import os, joblib, pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, roc_auc_score
from features import extract_features

BASE = os.path.dirname(os.path.abspath(__file__))
data = pd.read_csv(os.path.join(BASE, "..", "data", "sample_urls.csv"))
model = joblib.load(os.path.join(BASE, "model.pkl"))
vec = joblib.load(os.path.join(BASE, "vectorizer.pkl"))

Xf = [extract_features(u, use_whois=False) for u in data['url'].astype(str).tolist()]
X = vec.transform(Xf)
y = data['label'].astype(int).values

pred = model.predict(X)
proba = model.predict_proba(X)[:,1] if hasattr(model, "predict_proba") else None

print("Accuracy:", accuracy_score(y, pred))
print("Confusion matrix:\n", confusion_matrix(y, pred))
if proba is not None:
    print("ROC AUC:", roc_auc_score(y, proba))
