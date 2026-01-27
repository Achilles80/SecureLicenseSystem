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
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-6 text-white font-mono">
      <div className="max-w-3xl w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-green-500 mb-2">
            🔐 LICENSE VALIDATOR
          </h1>
          <p className="text-gray-500 text-sm">
            Public endpoint - Verify license authenticity using RSA digital signature verification
          </p>
          <div className="mt-2 inline-block px-3 py-1 bg-green-900/30 border border-green-500/50 rounded text-green-400 text-xs">
            🔓 NO AUTHENTICATION REQUIRED
          </div>
        </div>

        {/* Main Card */}
        <div className="border border-gray-800 bg-gray-900 p-8 rounded-xl shadow-2xl">
          <p className="text-gray-500 text-xs mb-6 text-center">
            SECURE VERIFICATION | RSA-2048 + SHA-256
          </p>

          {/* How it works */}
          <div className="bg-blue-900/20 border border-blue-500/30 p-4 rounded-lg mb-6 text-sm">
            <h3 className="font-bold text-blue-400 mb-3 flex items-center gap-2">
              <span className="text-lg">📋</span> How Validation Works:
            </h3>
            <ol className="space-y-2 text-gray-300">
              <li className="flex items-start gap-2">
                <span className="text-blue-400 font-bold">1.</span>
                <span>Base64 decoding extracts: <code className="text-cyan-400 bg-black/50 px-1 rounded">IV + Signature + Encrypted data</code></span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 font-bold">2.</span>
                <span>RSA public key verifies the digital signature</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 font-bold">3.</span>
                <span>If signature matches, data integrity is confirmed</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-400 font-bold">4.</span>
                <span>Any tampering will cause signature verification to <span className="text-red-400">FAIL</span></span>
              </li>
            </ol>
          </div>

          {/* Token Input */}
          <div className="mb-6">
            <label className="block text-gray-400 text-xs uppercase mb-2 tracking-wider">
              License Token
            </label>
            <textarea
              className="w-full h-36 bg-black border border-gray-700 p-4 rounded-lg font-mono text-xs text-green-400 focus:border-green-500 focus:ring-1 focus:ring-green-500 outline-none transition-all placeholder-gray-600 resize-none"
              placeholder="Paste your encrypted license token here..."
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                setResult(null);
              }}
            />
            {token && (
              <p className="text-gray-500 text-xs mt-1">
                Token length: {token.length} characters
              </p>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 mb-6">
            <button
              onClick={handleValidate}
              disabled={loading || !token}
              className="flex-1 bg-gradient-to-r from-green-600 to-green-700 hover:from-green-500 hover:to-green-600 disabled:from-gray-700 disabled:to-gray-700 disabled:cursor-not-allowed text-white font-bold py-4 px-6 rounded-lg transition-all shadow-lg hover:shadow-green-500/20 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <span className="animate-spin">⏳</span> Verifying...
                </>
              ) : (
                <>
                  <span>✅</span> VERIFY INTEGRITY
                </>
              )}
            </button>

            <button
              onClick={handleTamperTest}
              disabled={!token || loading}
              className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 disabled:from-gray-700 disabled:to-gray-700 disabled:cursor-not-allowed text-white font-bold py-4 px-6 rounded-lg transition-all shadow-lg hover:shadow-red-500/20 flex items-center gap-2"
              title="Simulate tampering by modifying the token"
            >
              <span>🔓</span> Tamper
            </button>
          </div>

          {/* Result Display */}
          {result && (
            <div
              className={`p-6 rounded-lg border ${result.valid
                  ? "bg-green-900/20 border-green-500/50"
                  : "bg-red-900/20 border-red-500/50"
                } animate-fadeIn`}
            >
              {result.valid ? (
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-4xl">✅</span>
                    <div>
                      <p className="text-green-400 font-bold text-xl">
                        VALID LICENSE
                      </p>
                      <p className="text-green-300 text-sm">{result.message}</p>
                    </div>
                  </div>
                  <div className="mt-4 text-sm bg-green-900/30 p-4 rounded-lg border border-green-500/30">
                    <p className="text-green-400 font-bold mb-2">🛡️ Security Verified:</p>
                    <div className="grid grid-cols-2 gap-2 text-green-300">
                      <div className="flex items-center gap-2">
                        <span className="text-green-500">✓</span> Base64 decoding successful
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-green-500">✓</span> RSA-PSS signature valid
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-green-500">✓</span> Data integrity confirmed
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-green-500">✓</span> No tampering detected
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div>
                  <div className="flex items-center gap-3 mb-3">
                    <span className="text-4xl">❌</span>
                    <div>
                      <p className="text-red-400 font-bold text-xl">
                        INVALID LICENSE
                      </p>
                      <p className="text-red-300 text-sm">
                        {result.error || result.message}
                      </p>
                    </div>
                  </div>
                  <div className="mt-4 text-sm bg-red-900/30 p-4 rounded-lg border border-red-500/30">
                    <p className="text-red-400 font-bold mb-2">⚠️ Possible Reasons:</p>
                    <div className="grid grid-cols-1 gap-1 text-red-300">
                      <div className="flex items-center gap-2">
                        <span className="text-red-500">•</span> License token was modified (tampering)
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-red-500">•</span> Invalid Base64 encoding
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-red-500">•</span> Signature verification failed
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-red-500">•</span> Expired or revoked license
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="mt-6 flex justify-between items-center">
          <a
            href="/"
            className="text-gray-400 hover:text-green-400 transition-colors flex items-center gap-2 text-sm"
          >
            ← Back to Login
          </a>
          <div className="text-gray-600 text-xs">
            SecureLicenseSystem v1.0
          </div>
          <a
            href="/dashboard"
            className="text-gray-400 hover:text-green-400 transition-colors flex items-center gap-2 text-sm"
          >
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
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="text-green-500 animate-pulse font-mono">
          <span className="text-2xl">🔐</span> Loading Validator...
        </div>
      </div>
    }>
      <ValidateContent />
    </Suspense>
  );
}