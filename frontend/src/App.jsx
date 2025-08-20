import { useState } from "react";

function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const apiUrl = "http://127.0.0.1:5000/predict_url"; // backend endpoint

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setResult(null);

    const trimmed = (url || "").trim();
    if (!trimmed) {
      setError("Please enter a URL to scan.");
      return;
    }

    setLoading(true);
    try {
      const resp = await fetch(apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed })
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error("Server error: " + (text || resp.status));
      }

      const data = await resp.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Network error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ fontFamily: "Inter, system-ui, Arial", maxWidth: 760, margin: "36px auto", padding: 16 }}>
      <h1 style={{ marginBottom: 6 }}>PhishGuard 🔒</h1>
      <p style={{ color: "#555", marginTop: 0 }}>Paste a URL below to check if it's safe or phishing.</p>

      <form onSubmit={handleSubmit} style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/reset-password"
          style={{ flex: 1, padding: 10, borderRadius: 8, border: "1px solid #ccc" }}
        />
        <button type="submit" style={{ padding: "10px 14px", borderRadius: 8, border: 0, background: "#111827", color: "white", cursor: "pointer" }}>
          {loading ? "Checking..." : "Check"}
        </button>
      </form>

      {error && (
        <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: "#fee2e2", color: "#991b1b" }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 14 }}>
          <div style={{
            padding: 14,
            borderRadius: 10,
            background: result.label === 1 ? "#fee2e2" : "#dcfce7",
            border: result.label === 1 ? "1px solid #fca5a5" : "1px solid #bbf7d0"
          }}>
            <strong>Result:</strong> {result.label === 1 ? "Phishing ⚠️" : "Safe ✅"}
            <div style={{ marginTop: 8, color: "#333" }}>
              <strong>Score:</strong> {(typeof result.score === "number") ? result.score.toFixed(2) : String(result.score)}
            </div>
            {Array.isArray(result.reasons) && result.reasons.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <strong>Why:</strong>
                <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {result.reasons.map((r, i) => (
                    <span key={i} style={{ padding: "6px 8px", borderRadius: 999, background: "#f3f4f6", fontSize: 13 }}>{r}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* raw JSON for debugging (optional) */}
          <details style={{ marginTop: 10 }}>
            <summary style={{ cursor: "pointer" }}>Show raw response (for debugging)</summary>
            <pre style={{ whiteSpace: "pre-wrap", marginTop: 8, background: "#111827", color: "#fff", padding: 10, borderRadius: 8 }}>
              {JSON.stringify(result, null, 2)}
            </pre>
          </details>
        </div>
      )}

      <footer style={{ marginTop: 26, fontSize: 13, color: "#666" }}>
        Make sure the PhishGuard backend is running at <code>http://127.0.0.1:5000</code>.
      </footer>
    </div>
  );
}

export default App;
