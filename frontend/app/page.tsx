"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [showOtpModal, setShowOtpModal] = useState(false);
  const [pendingUsername, setPendingUsername] = useState("");
  const [loading, setLoading] = useState(false);
  const [guestLoading, setGuestLoading] = useState(false);
  const [error, setError] = useState("");
  const [otpTimer, setOtpTimer] = useState(0); // Timer in seconds

  const router = useRouter();

  // OTP countdown timer effect
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (otpTimer > 0) {
      interval = setInterval(() => {
        setOtpTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [otpTimer]);

  // Format seconds to MM:SS
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
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
        setOtpTimer(300); // 5 minutes = 300 seconds
      } else if (!res.ok) {
        setError(data.error || "Login failed");
      }
    } catch (err) {
      setError("Failed to connect to backend. Is Python running?");
    } finally {
      setLoading(false);
    }
  };

  const handleGuestLogin = async () => {
    setGuestLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/auth/guest-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
        setError(data.error || "Guest login failed");
      }
    } catch (err) {
      setError("Failed to connect to backend. Is Python running?");
    } finally {
      setGuestLoading(false);
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
          SECURE LOGIN
        </h1>
        <p className="text-center text-gray-500 text-sm mb-6">
          Multi-Factor Authentication Enabled
        </p>

        {error && (
          <div className="bg-red-900/30 border border-red-500 text-red-300 p-3 rounded mb-4 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="flex flex-col gap-4">
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

          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-bold p-3 rounded mt-2 transition-colors"
          >
            {loading ? "Processing..." : "AUTHENTICATE"}
          </button>
        </form>

        {/* Guest Login Button */}
        <button
          onClick={handleGuestLogin}
          disabled={guestLoading}
          className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white font-bold p-3 rounded mt-3 transition-colors flex items-center justify-center gap-2"
        >
          {guestLoading ? (
            "Logging in..."
          ) : (
            <>
              <span>👤</span> LOGIN AS GUEST
            </>
          )}
        </button>
        <p className="text-center text-gray-500 text-xs mt-1">
          Guest can only validate licenses (no MFA required)
        </p>

        {/* Links */}
        <div className="mt-6 pt-4 border-t border-gray-800 flex flex-col gap-2">
          <Link
            href="/signup"
            className="text-center text-sm text-blue-400 hover:text-blue-300 underline"
          >
            Need an account? Sign Up
          </Link>
          <Link
            href="/reset-password"
            className="text-center text-sm text-orange-400 hover:text-orange-300 underline"
          >
            Forgot Password?
          </Link>
          <Link
            href="/validate"
            className="text-center text-sm text-green-400 hover:underline"
          >
            Go to Public Validator →
          </Link>
        </div>
      </div>

      {/* OTP Modal */}
      {showOtpModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-gray-900 p-8 rounded-lg border border-gray-700 max-w-sm w-full">
            <h2 className="text-xl font-bold mb-2 text-center text-green-400">
              🔐 MFA Verification
            </h2>
            <p className="text-gray-400 text-sm text-center mb-2">
              Enter the 6-digit OTP code shown in the server console
            </p>

            {/* OTP Timer Display */}
            <div className={`text-center mb-4 p-2 rounded border ${otpTimer > 60
              ? "bg-green-900/20 border-green-500/50 text-green-400"
              : otpTimer > 0
                ? "bg-red-900/20 border-red-500/50 text-red-400 animate-pulse"
                : "bg-gray-800 border-gray-700 text-gray-500"
              }`}>
              {otpTimer > 0 ? (
                <div className="flex items-center justify-center gap-2">
                  <span className="font-mono text-xl font-bold">{formatTime(otpTimer)}</span>
                  <span className="text-xs">remaining</span>
                </div>
              ) : (
                <div className="text-sm">
                  ⚠️ OTP Expired - Please request a new one
                </div>
              )}
            </div>

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
              disabled={loading || otp.length !== 6 || otpTimer === 0}
              className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white font-bold p-3 rounded transition-colors"
            >
              {loading ? "Verifying..." : "VERIFY OTP"}
            </button>

            <button
              onClick={() => {
                setShowOtpModal(false);
                setOtp("");
                setError("");
                setOtpTimer(0);
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