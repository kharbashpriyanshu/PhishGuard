from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import tldextract
import Levenshtein

app = Flask(__name__)
CORS(app)

# Load your trained model
model = joblib.load("model.pkl")

# Known legitimate domains (you can add more)
trusted_domains = ["facebook.com", "google.com", "yahoo.com", "amazon.com", "paypal.com"]

# Function to check similarity
def is_domain_suspicious(domain):
    for trusted in trusted_domains:
        distance = Levenshtein.distance(domain, trusted)
        if distance <= 3:  # small difference = suspicious
            return True, trusted
    return False, None

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Extract domain
        extracted = tldextract.extract(url)
        domain = extracted.domain + "." + extracted.suffix

        # 1. Domain similarity check
        suspicious, matched = is_domain_suspicious(domain)
        if suspicious and domain != matched:
            return jsonify({"prediction": "Phishing", "reason": f"Looks similar to {matched}"}), 200

        # 2. Use ML model as fallback
        prediction = model.predict([url])[0]

        result = "Phishing" if prediction == 1 else "Legitimate"
        return jsonify({"prediction": result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
