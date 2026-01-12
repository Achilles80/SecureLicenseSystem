"use client";
import { useState } from 'react';

export default function Validate() {
  const [token, setToken] = useState('');
  const [result, setResult] = useState<any>(null);

  const handleValidate = async () => {
    try {
      const res = await fetch('http://127.0.0.1:5000/validate_license', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_key: token }),
      });
      const data = await res.json();
      setResult(data);
    } catch(err) {
      setResult({ valid: false, error: "Connection Failed" });
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-6 text-gray-800">
      <div className="bg-white p-8 rounded-xl shadow-lg max-w-2xl w-full">
        <h1 className="text-2xl font-bold mb-6">License Validator</h1>
        <textarea 
          className="w-full h-32 bg-gray-50 border border-gray-300 p-4 rounded mb-4 font-mono text-xs"
          placeholder="Paste License Key here..."
          value={token}
          onChange={(e) => setToken(e.target.value)}
        />
        <button onClick={handleValidate} className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold p-3 rounded">
          VERIFY INTEGRITY
        </button>

        {result && (
          <div className={`mt-6 p-4 rounded border ${result.valid ? 'bg-green-50 border-green-200 text-green-800' : 'bg-red-50 border-red-200 text-red-800'}`}>
            {result.valid ? "✅ VALID LICENSE (Signature Verified)" : `❌ INVALID: ${result.error}`}
          </div>
        )}
      </div>
    </div>
  );
}