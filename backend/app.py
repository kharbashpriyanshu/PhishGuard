from flask import Flask, request, jsonify
from features import extract_features  # make sure features.py is in same folder

app = Flask(__name__)

@app.route('/features', methods=['POST'])
def get_features():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_features(url, do_whois=False)
    return jsonify({"features": features})

if __name__ == "__main__":
    # explicitly set host and port
    app.run(host="127.0.0.1", port=5000, debug=True)
