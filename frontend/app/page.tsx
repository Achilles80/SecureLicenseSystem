"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [isRegistering, setIsRegistering] = useState(false);
  const [showOtpModal, setShowOtpModal] = useState(false);
  const [pendingUsername, setPendingUsername] = useState("");
  const [role, setRole] = useState("user");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const router = useRouter();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, role }),
      });
      const data = await res.json();

      if (res.ok) {
        alert("✅ Registration Successful! Please Login.");
        setIsRegistering(false);
        setUsername("");
        setPassword("");
      } else {
        setError(data.error || "Registration failed");
      }
    } catch (err) {
      setError("Failed to connect to backend. Is Python running?");
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();

      if (res.ok && data.mfa_required) {
        // Show OTP modal for MFA
        setPendingUsername(username);
        setShowOtpModal(true);
      } else if (!res.ok) {
        setError(data.error || "Login failed");
      }
    } catch (err) {
      setError("Failed to connect to backend. Is Python running?");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: pendingUsername, otp }),
      });
      const data = await res.json();

      if (res.ok) {
        // Store JWT token and user info
        localStorage.setItem("token", data.token);
        localStorage.setItem("username", data.username);
        localStorage.setItem("role", data.role);

        // Redirect to dashboard
        router.push("/dashboard");
      } else {
        setError(data.error || "OTP verification failed");
      }
    } catch (err) {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-black text-white p-6">
      <div className="w-full max-w-md bg-gray-900 p-8 rounded-lg border border-gray-800 shadow-xl">
        <h1 className="text-3xl font-bold mb-2 text-center bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
          {isRegistering ? "SECURE REGISTER" : "SECURE LOGIN"}
        </h1>
        <p className="text-center text-gray-500 text-sm mb-6">
          Multi-Factor Authentication Enabled
        </p>

        {error && (
          <div className="bg-red-900/30 border border-red-500 text-red-300 p-3 rounded mb-4 text-sm">
            {error}
          </div>
        )}

        <form
          onSubmit={isRegistering ? handleRegister : handleLogin}
          className="flex flex-col gap-4"
        >
          <input
            className="bg-gray-800 border border-gray-700 p-3 rounded text-white focus:border-blue-500 outline-none"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          <input
            className="bg-gray-800 border border-gray-700 p-3 rounded text-white focus:border-blue-500 outline-none"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          {isRegistering && (
            <select
              className="bg-gray-800 border border-gray-700 p-3 rounded text-white focus:border-blue-500 outline-none"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="user">User (Can validate only)</option>
              <option value="admin">Admin (Full access)</option>
              <option value="guest">Guest (Limited access)</option>
            </select>
          )}

          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-bold p-3 rounded mt-2 transition-colors"
          >
            {loading
              ? "Processing..."
              : isRegistering
                ? "CREATE ACCOUNT"
                : "AUTHENTICATE"}
          </button>
        </form>

        <button
          onClick={() => {
            setIsRegistering(!isRegistering);
            setError("");
          }}
          className="mt-4 text-sm text-gray-400 hover:text-white underline w-full text-center"
        >
          {isRegistering
            ? "Already have an account? Login"
            : "Need an account? Register"}
        </button>

        <div className="mt-4 text-center">
          <a
            href="/validate"
            className="text-sm text-green-400 hover:underline"
          >
            Go to Public Validator →
          </a>
        </div>
      </div>

      {/* OTP Modal */}
      {showOtpModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-gray-900 p-8 rounded-lg border border-gray-700 max-w-sm w-full">
            <h2 className="text-xl font-bold mb-2 text-center text-green-400">
              🔐 MFA Verification
            </h2>
            <p className="text-gray-400 text-sm text-center mb-4">
              Enter the 6-digit OTP code shown in the server console
            </p>

            {error && (
              <div className="bg-red-900/30 border border-red-500 text-red-300 p-2 rounded mb-4 text-sm text-center">
                {error}
              </div>
            )}

            <input
              className="w-full bg-gray-800 border border-gray-700 p-4 rounded text-white text-center text-2xl tracking-widest mb-4 focus:border-green-500 outline-none"
              placeholder="000000"
              maxLength={6}
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
              autoFocus
            />

            <button
              onClick={handleVerifyOtp}
              disabled={loading || otp.length !== 6}
              className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white font-bold p-3 rounded transition-colors"
            >
              {loading ? "Verifying..." : "VERIFY OTP"}
            </button>

            <button
              onClick={() => {
                setShowOtpModal(false);
                setOtp("");
                setError("");
              }}
              className="w-full mt-2 text-gray-400 hover:text-white text-sm underline"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}