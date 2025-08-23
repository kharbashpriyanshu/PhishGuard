from flask import Flask, request, jsonify
import joblib

# Load model and vectorizer
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

app = Flask(__name__)

@app.route("/predict_url", methods=["POST"])
def predict_url():
    """POST endpoint to check URL (for API calls)."""
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = vectorizer.transform([url])
    prediction = model.predict(features)[0]
    score = model.predict_proba(features)[0][prediction]

    label = "phishing" if prediction == 1 else "legitimate"

    return jsonify({
        "url": url,
        "label": label,
        "score": float(score)
    })


@app.route("/check_url", methods=["GET"])
def check_url():
    """GET endpoint to test directly in the browser."""
    url = request.args.get("url")

    if not url:
        return jsonify({"error": "Please provide a URL as a query parameter, e.g., /check_url?url=example.com"}), 400

    features = vectorizer.transform([url])
    prediction = model.predict(features)[0]
    score = model.predict_proba(features)[0][prediction]

    label = "phishing" if prediction == 1 else "legitimate"

    return jsonify({
        "url": url,
        "label": label,
        "score": float(score)
    })


if __name__ == "__main__":
    app.run(debug=True)
