"use client";
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const router = useRouter();

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    const endpoint = isRegistering ? '/register' : '/login';
    
    try {
      const res = await fetch(`http://127.0.0.1:5000${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();

      if (res.ok) {
        if (isRegistering) {
          alert("Registration Successful! Please Login.");
          setIsRegistering(false);
        } else {
          // [Rubric] MFA Logic
          if (data.mfa_required) {
             const otp = prompt("ENTER OTP (Check Console/Server Log for '1234'):");
             if (otp === "1234") {
                 router.push('/dashboard');
             } else {
                 alert("Invalid OTP");
             }
          }
        }
      } else {
        alert("Error: " + data.error);
      }
    } catch (err) {
      alert("Failed to connect to backend. Is Python running?");
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-black text-white p-6">
      <div className="w-full max-w-md bg-gray-900 p-8 rounded-lg border border-gray-800 shadow-xl">
        <h1 className="text-3xl font-bold mb-6 text-center bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
          {isRegistering ? 'SECURE REGISTER' : 'SECURE LOGIN'}
        </h1>
        
        <form onSubmit={handleAuth} className="flex flex-col gap-4">
          <input 
            className="bg-gray-800 border border-gray-700 p-3 rounded text-white" 
            placeholder="Username"
            value={username} 
            onChange={(e) => setUsername(e.target.value)} 
            required
          />
          <input 
            className="bg-gray-800 border border-gray-700 p-3 rounded text-white" 
            type="password" 
            placeholder="Password"
            value={password} 
            onChange={(e) => setPassword(e.target.value)} 
            required
          />
          <button className="bg-blue-600 hover:bg-blue-700 text-white font-bold p-3 rounded mt-2">
            {isRegistering ? 'CREATE ACCOUNT' : 'AUTHENTICATE'}
          </button>
        </form>

        <button 
          onClick={() => setIsRegistering(!isRegistering)}
          className="mt-4 text-sm text-gray-400 hover:text-white underline w-full text-center"
        >
          {isRegistering ? "Already have an account? Login" : "Need an account? Register"}
        </button>
        <div className="mt-4 text-center">
            <a href="/validate" className="text-sm text-green-400 hover:underline">Go to Public Validator →</a>
        </div>
      </div>
    </div>
  );
}