"use client";
import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";

function ValidateContent() {
  const searchParams = useSearchParams();
  const [token, setToken] = useState("");
  const [result, setResult] = useState<{
    valid: boolean;
    message?: string;
    error?: string;
  } | null>(null);
  const [loading, setLoading] = useState(false);

  // Read token from URL query param on mount
  useEffect(() => {
    const tokenFromUrl = searchParams.get("token");
    if (tokenFromUrl) {
      setToken(decodeURIComponent(tokenFromUrl));
    }
  }, [searchParams]);

  const handleValidate = async () => {
    setLoading(true);
    setResult(null);

    try {
      const res = await fetch("http://127.0.0.1:5000/validate_public", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ license_key: token }),
      });
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setResult({ valid: false, error: "Connection Failed - Is backend running?" });
    } finally {
      setLoading(false);
    }
  };

  const handleTamperTest = () => {
    if (token.length > 10) {
      // Modify a character to simulate tampering
      const tamperedToken = token.slice(0, -5) + "XXXXX";
      setToken(tamperedToken);
      setResult(null);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6 text-gray-800">
      <div className="bg-white p-8 rounded-xl shadow-lg max-w-2xl w-full">
        <h1 className="text-2xl font-bold mb-2">🔐 License Validator</h1>
        <p className="text-gray-500 text-sm mb-6">
          Public endpoint - Verify license authenticity using RSA digital
          signature verification
        </p>

        {/* How it works */}
        <div className="bg-blue-50 border border-blue-200 p-4 rounded mb-6 text-sm">
          <h3 className="font-bold text-blue-800 mb-2">How Validation Works:</h3>
          <ol className="list-decimal list-inside text-blue-700 space-y-1">
            <li>Base64 decoding extracts: IV + Signature + Encrypted data</li>
            <li>RSA public key verifies the digital signature</li>
            <li>If signature matches, data integrity is confirmed</li>
            <li>Any tampering will cause signature verification to fail</li>
          </ol>
        </div>

        <textarea
          className="w-full h-32 bg-gray-50 border border-gray-300 p-4 rounded mb-4 font-mono text-xs focus:border-blue-500 outline-none"
          placeholder="Paste License Key here..."
          value={token}
          onChange={(e) => {
            setToken(e.target.value);
            setResult(null);
          }}
        />

        <div className="flex gap-2 mb-4">
          <button
            onClick={handleValidate}
            disabled={loading || !token}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-bold p-3 rounded transition-colors"
          >
            {loading ? "Verifying..." : "✅ VERIFY INTEGRITY"}
          </button>

          <button
            onClick={handleTamperTest}
            disabled={!token || loading}
            className="bg-red-600 hover:bg-red-700 disabled:bg-gray-400 text-white font-bold px-4 rounded transition-colors"
            title="Simulate tampering by modifying the token"
          >
            🔓 Tamper
          </button>
        </div>

        {result && (
          <div
            className={`p-4 rounded border ${result.valid
              ? "bg-green-50 border-green-200"
              : "bg-red-50 border-red-200"
              }`}
          >
            {result.valid ? (
              <div>
                <p className="text-green-800 font-bold text-lg">
                  ✅ VALID LICENSE
                </p>
                <p className="text-green-700 text-sm mt-1">{result.message}</p>
                <div className="mt-3 text-xs text-green-600 bg-green-100 p-2 rounded">
                  <strong>Security Verified:</strong>
                  <ul className="list-disc list-inside mt-1">
                    <li>Base64 decoding successful</li>
                    <li>RSA-PSS signature valid (2048-bit)</li>
                    <li>Data integrity confirmed</li>
                    <li>No tampering detected</li>
                  </ul>
                </div>
              </div>
            ) : (
              <div>
                <p className="text-red-800 font-bold text-lg">
                  ❌ INVALID LICENSE
                </p>
                <p className="text-red-700 text-sm mt-1">
                  {result.error || result.message}
                </p>
                <div className="mt-3 text-xs text-red-600 bg-red-100 p-2 rounded">
                  <strong>Possible Reasons:</strong>
                  <ul className="list-disc list-inside mt-1">
                    <li>License token was modified (tampering)</li>
                    <li>Invalid Base64 encoding</li>
                    <li>Signature verification failed</li>
                    <li>Expired or revoked license</li>
                  </ul>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Navigation */}
        <div className="mt-6 flex justify-between text-sm">
          <a href="/" className="text-blue-600 hover:underline">
            ← Back to Login
          </a>
          <a href="/dashboard" className="text-green-600 hover:underline">
            Go to Dashboard →
          </a>
        </div>
      </div>
    </div>
  );
}

export default function Validate() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-gray-500">Loading...</div>
      </div>
    }>
      <ValidateContent />
    </Suspense>
  );
}