"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

interface PasswordValidation {
    minLength: boolean;
    hasUppercase: boolean;
    hasLowercase: boolean;
    hasSpecial: boolean;
}

type Step = "username" | "otp" | "newPassword";

export default function ResetPasswordPage() {
    const [step, setStep] = useState<Step>("username");
    const [username, setUsername] = useState("");
    const [otp, setOtp] = useState("");
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");
    const [passwordValidation, setPasswordValidation] = useState<PasswordValidation>({
        minLength: false,
        hasUppercase: false,
        hasLowercase: false,
        hasSpecial: false,
    });

    const router = useRouter();

    // Real-time password validation
    useEffect(() => {
        setPasswordValidation({
            minLength: newPassword.length >= 8,
            hasUppercase: /[A-Z]/.test(newPassword),
            hasLowercase: /[a-z]/.test(newPassword),
            hasSpecial: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(newPassword),
        });
    }, [newPassword]);

    const isPasswordValid = Object.values(passwordValidation).every(Boolean);
    const passwordsMatch = newPassword === confirmPassword && confirmPassword !== "";

    // Step 1: Request OTP
    const handleRequestOtp = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");

        try {
            const res = await fetch("http://127.0.0.1:5000/auth/forgot-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username }),
            });
            const data = await res.json();

            if (res.ok) {
                setStep("otp");
                setSuccess("OTP has been sent! Check the server console.");
            } else {
                setError(data.error || "Failed to send OTP");
            }
        } catch (err) {
            setError("Failed to connect to backend. Is Python running?");
        } finally {
            setLoading(false);
        }
    };

    // Step 2: Verify OTP and move to new password
    const handleVerifyOtp = async (e: React.FormEvent) => {
        e.preventDefault();
        setError("");
        setSuccess("");
        setStep("newPassword");
    };

    // Step 3: Reset password
    const handleResetPassword = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");

        if (!isPasswordValid) {
            setError("Please fix the password requirements highlighted in red");
            setLoading(false);
            return;
        }

        if (!passwordsMatch) {
            setError("Passwords do not match");
            setLoading(false);
            return;
        }

        try {
            const res = await fetch("http://127.0.0.1:5000/auth/reset-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username,
                    otp,
                    new_password: newPassword,
                }),
            });
            const data = await res.json();

            if (res.ok) {
                alert("✅ Password reset successful! Please login with your new password.");
                router.push("/");
            } else {
                if (data.password_errors) {
                    setError(data.password_errors.join(", "));
                } else {
                    setError(data.error || "Password reset failed");
                }
            }
        } catch (err) {
            setError("Failed to connect to backend. Is Python running?");
        } finally {
            setLoading(false);
        }
    };

    const ValidationItem = ({
        valid,
        text,
    }: {
        valid: boolean;
        text: string;
    }) => (
        <div
            className={`flex items-center gap-2 text-sm ${valid ? "text-green-400" : "text-red-400"
                }`}
        >
            <span>{valid ? "✓" : "✗"}</span>
            <span>{text}</span>
        </div>
    );

    return (
        <div className="flex min-h-screen flex-col items-center justify-center bg-black text-white p-6">
            <div className="w-full max-w-md bg-gray-900 p-8 rounded-lg border border-gray-800 shadow-xl">
                <h1 className="text-3xl font-bold mb-2 text-center bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">
                    RESET PASSWORD
                </h1>
                <p className="text-center text-gray-500 text-sm mb-6">
                    {step === "username" && "Enter your username to receive a reset OTP"}
                    {step === "otp" && "Enter the OTP from the server console"}
                    {step === "newPassword" && "Create your new secure password"}
                </p>

                {/* Progress indicator */}
                <div className="flex justify-center gap-2 mb-6">
                    <div
                        className={`w-3 h-3 rounded-full ${step === "username" ? "bg-orange-500" : "bg-gray-600"
                            }`}
                    />
                    <div
                        className={`w-3 h-3 rounded-full ${step === "otp" ? "bg-orange-500" : "bg-gray-600"
                            }`}
                    />
                    <div
                        className={`w-3 h-3 rounded-full ${step === "newPassword" ? "bg-orange-500" : "bg-gray-600"
                            }`}
                    />
                </div>

                {error && (
                    <div className="bg-red-900/30 border border-red-500 text-red-300 p-3 rounded mb-4 text-sm">
                        {error}
                    </div>
                )}

                {success && (
                    <div className="bg-green-900/30 border border-green-500 text-green-300 p-3 rounded mb-4 text-sm">
                        {success}
                    </div>
                )}

                {/* Step 1: Username */}
                {step === "username" && (
                    <form onSubmit={handleRequestOtp} className="flex flex-col gap-4">
                        <div>
                            <label className="text-gray-400 text-sm mb-1 block">
                                Username
                            </label>
                            <input
                                className="w-full bg-gray-800 border border-gray-700 p-3 rounded text-white focus:border-orange-500 outline-none"
                                placeholder="Enter your username"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                required
                                autoFocus
                            />
                        </div>

                        <button
                            type="submit"
                            disabled={loading || !username}
                            className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white font-bold p-3 rounded mt-2 transition-colors"
                        >
                            {loading ? "Sending OTP..." : "SEND RESET OTP"}
                        </button>
                    </form>
                )}

                {/* Step 2: OTP Verification */}
                {step === "otp" && (
                    <form onSubmit={handleVerifyOtp} className="flex flex-col gap-4">
                        <div className="bg-blue-900/20 border border-blue-800 p-3 rounded text-sm text-blue-300 mb-2">
                            <p>
                                📱 Check the <strong>server console</strong> for your 6-digit
                                OTP code
                            </p>
                        </div>

                        <div>
                            <label className="text-gray-400 text-sm mb-1 block">
                                OTP Code
                            </label>
                            <input
                                className="w-full bg-gray-800 border border-gray-700 p-4 rounded text-white text-center text-2xl tracking-widest focus:border-orange-500 outline-none"
                                placeholder="000000"
                                maxLength={6}
                                value={otp}
                                onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
                                required
                                autoFocus
                            />
                        </div>

                        <button
                            type="submit"
                            disabled={otp.length !== 6}
                            className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 text-white font-bold p-3 rounded mt-2 transition-colors"
                        >
                            VERIFY OTP
                        </button>

                        <button
                            type="button"
                            onClick={() => {
                                setStep("username");
                                setOtp("");
                                setError("");
                                setSuccess("");
                            }}
                            className="text-gray-400 hover:text-white text-sm underline"
                        >
                            ← Back to username
                        </button>
                    </form>
                )}

                {/* Step 3: New Password */}
                {step === "newPassword" && (
                    <form onSubmit={handleResetPassword} className="flex flex-col gap-4">
                        <div>
                            <label className="text-gray-400 text-sm mb-1 block">
                                New Password
                            </label>
                            <input
                                className={`w-full bg-gray-800 border p-3 rounded text-white outline-none transition-colors ${newPassword === ""
                                        ? "border-gray-700"
                                        : isPasswordValid
                                            ? "border-green-500"
                                            : "border-red-500"
                                    }`}
                                type="password"
                                placeholder="Create a strong password"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                required
                                autoFocus
                            />
                        </div>

                        {/* Password Requirements */}
                        <div className="bg-gray-800/50 p-3 rounded border border-gray-700">
                            <p className="text-gray-400 text-xs mb-2 font-semibold">
                                PASSWORD REQUIREMENTS:
                            </p>
                            <div className="grid grid-cols-1 gap-1">
                                <ValidationItem
                                    valid={passwordValidation.minLength}
                                    text="At least 8 characters"
                                />
                                <ValidationItem
                                    valid={passwordValidation.hasUppercase}
                                    text="At least one uppercase letter (A-Z)"
                                />
                                <ValidationItem
                                    valid={passwordValidation.hasLowercase}
                                    text="At least one lowercase letter (a-z)"
                                />
                                <ValidationItem
                                    valid={passwordValidation.hasSpecial}
                                    text="At least one special character (!@#$%^&*)"
                                />
                            </div>
                        </div>

                        <div>
                            <label className="text-gray-400 text-sm mb-1 block">
                                Confirm New Password
                            </label>
                            <input
                                className={`w-full bg-gray-800 border p-3 rounded text-white outline-none transition-colors ${confirmPassword === ""
                                        ? "border-gray-700"
                                        : passwordsMatch
                                            ? "border-green-500"
                                            : "border-red-500"
                                    }`}
                                type="password"
                                placeholder="Confirm your new password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                required
                            />
                            {confirmPassword !== "" && !passwordsMatch && (
                                <p className="text-red-400 text-xs mt-1">
                                    Passwords do not match
                                </p>
                            )}
                        </div>

                        <button
                            type="submit"
                            disabled={loading || !isPasswordValid || !passwordsMatch}
                            className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-bold p-3 rounded mt-2 transition-colors"
                        >
                            {loading ? "Resetting Password..." : "RESET PASSWORD"}
                        </button>

                        <button
                            type="button"
                            onClick={() => {
                                setStep("otp");
                                setNewPassword("");
                                setConfirmPassword("");
                                setError("");
                            }}
                            className="text-gray-400 hover:text-white text-sm underline"
                        >
                            ← Back to OTP
                        </button>
                    </form>
                )}

                <div className="mt-6 pt-4 border-t border-gray-800">
                    <Link
                        href="/"
                        className="block text-center text-sm text-gray-400 hover:text-white underline"
                    >
                        ← Back to Login
                    </Link>
                </div>
            </div>
        </div>
    );
}
