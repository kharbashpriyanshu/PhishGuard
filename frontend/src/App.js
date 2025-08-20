import React, { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:5000/predict_url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      setResult(data.prediction);
    } catch (error) {
  console.error("Request failed:", error);
  setResult({ error: "Something went wrong!" });
}


    setLoading(false);
  };

  return (
    <div className="app-container">
      <div className="card">
        <h1 className="title">🔒 PhishGuard</h1>
        <p className="subtitle">Check if a URL is Safe or Phishing 🚨</p>

        <form onSubmit={handleSubmit} className="form">
          <input
            type="text"
            placeholder="Enter URL (e.g. http://example.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="input-box"
            required
          />
          <button type="submit" className="btn">Check</button>
        </form>

        {loading && <div className="spinner"></div>}

        {result && (
          <div className={`result ${result === "phishing" ? "phishing" : "legit"}`}>
            {result === "phishing" ? "⚠️ Phishing Website!" : "✅ Legitimate Website"}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
