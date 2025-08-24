import pandas as pd
from features import extract_features, FEATURE_ORDER
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# -------------------- Load CSV --------------------
csv_file = "phishing.csv"
df = pd.read_csv(csv_file)

# Inspect columns
print("CSV Columns:", df.columns.tolist())

# Attempt to normalize column names
df.columns = [c.strip().lower() for c in df.columns]

# Keep only 'url' and 'label' columns if they exist
if "url" not in df.columns or "label" not in df.columns:
    raise ValueError("CSV must contain 'url' and 'label' columns.")

df = df[["url", "label"]].dropna()

# Map string labels to integers if necessary
unique_labels = df["label"].unique()
print("Unique labels before mapping:", unique_labels)

# If labels are not numeric, map them
if df["label"].dtype == object:
    # Automatically map to 0/1
    mapping = {label: idx for idx, label in enumerate(sorted(unique_labels))}
    print("Mapping labels:", mapping)
    df["label"] = df["label"].map(mapping)

df["label"] = df["label"].astype(int)
print("Unique labels after mapping:", df["label"].unique())

# -------------------- Extract features --------------------
features_list = []
labels = []

print(f"[INFO] Extracting features from {len(df)} URLs...")

for i, row in enumerate(df.itertuples(index=False), 1):
    url = getattr(row, "url")
    label = getattr(row, "label")
    try:
        feats = extract_features(url)
        # Keep only numeric features in FEATURE_ORDER
        feature_vector = [feats[f] for f in FEATURE_ORDER]
        features_list.append(feature_vector)
        labels.append(label)
    except Exception as e:
        print(f"[WARN] Failed to extract features from {url}: {e}")

    if i % 500 == 0:
        print(f"[INFO] Processed {i}/{len(df)} URLs")

print(f"[INFO] Finished feature extraction. Total processed: {len(features_list)}")

# -------------------- Train/test split --------------------
X_train, X_test, y_train, y_test = train_test_split(
    features_list, labels, test_size=0.2, random_state=42
)

# -------------------- Train Random Forest --------------------
print("[INFO] Training RandomForestClassifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# -------------------- Evaluate --------------------
score = model.score(X_test, y_test)
print(f"[INFO] Test accuracy: {score:.4f}")

# -------------------- Save model --------------------
joblib.dump(model, "phishguard_model.pkl")
print("[INFO] Model saved as phishguard_model.pkl")
