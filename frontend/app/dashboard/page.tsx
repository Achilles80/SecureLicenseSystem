"use client";
import { useState } from 'react';

export default function Dashboard() {
  const [clientName, setClientName] = useState('');
  const [generatedKey, setGeneratedKey] = useState('');

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetch('http://127.0.0.1:5000/generate_license', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'admin', client_name: clientName }),
    });
    const data = await res.json();
    if (res.ok) setGeneratedKey(data.license_key);
    else alert(data.error);
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white p-10 font-mono">
      <div className="max-w-4xl mx-auto border border-gray-800 bg-gray-900 p-8 rounded-xl shadow-2xl">
        <h1 className="text-2xl font-bold text-green-500 mb-2">ADMIN CONSOLE</h1>
        <p className="text-gray-500 text-sm mb-8">SECURE CONNECTION ESTABLISHED | AES-256 ENCRYPTION ACTIVE</p>

        <form onSubmit={handleGenerate} className="flex gap-4 mb-8">
          <input 
            className="flex-1 bg-black border border-gray-700 p-4 rounded text-green-400"
            placeholder="Enter Client Name"
            value={clientName}
            onChange={(e) => setClientName(e.target.value)}
          />
          <button className="bg-green-600 hover:bg-green-700 text-black font-bold px-8 rounded">
            GENERATE
          </button>
        </form>

        {generatedKey && (
          <div className="bg-black p-6 rounded border border-green-500/30 break-all">
            <h3 className="text-xs text-gray-500 mb-2 uppercase">Encrypted Token</h3>
            <code className="text-xs text-green-300">{generatedKey}</code>
          </div>
        )}
      </div>
    </div>
  );
}