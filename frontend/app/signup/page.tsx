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

export default function SignupPage() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
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
            minLength: password.length >= 8,
            hasUppercase: /[A-Z]/.test(password),
            hasLowercase: /[a-z]/.test(password),
            hasSpecial: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password),
        });
    }, [password]);

    const isPasswordValid = Object.values(passwordValidation).every(Boolean);
    const passwordsMatch = password === confirmPassword && confirmPassword !== "";

    const handleSignup = async (e: React.FormEvent) => {
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
            const res = await fetch("http://127.0.0.1:5000/auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });
            const data = await res.json();

            if (res.ok) {
                alert("✅ Registration Successful! Please Login.");
                router.push("/");
            } else {
                if (data.password_errors) {
                    setError(data.password_errors.join(", "));
                } else {
                    setError(data.error || "Registration failed");
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
                <h1 className="text-3xl font-bold mb-2 text-center bg-gradient-to-r from-green-400 to-blue-500 bg-clip-text text-transparent">
                    CREATE ACCOUNT
                </h1>
                <p className="text-center text-gray-500 text-sm mb-6">
                    Secure Registration with Strong Password Policy
                </p>

                {error && (
                    <div className="bg-red-900/30 border border-red-500 text-red-300 p-3 rounded mb-4 text-sm">
                        {error}
                    </div>
                )}

                <form onSubmit={handleSignup} className="flex flex-col gap-4">
                    <div>
                        <label className="text-gray-400 text-sm mb-1 block">Username</label>
                        <input
                            className="w-full bg-gray-800 border border-gray-700 p-3 rounded text-white focus:border-blue-500 outline-none"
                            placeholder="Choose a username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                        />
                    </div>

                    <div>
                        <label className="text-gray-400 text-sm mb-1 block">Password</label>
                        <input
                            className={`w-full bg-gray-800 border p-3 rounded text-white outline-none transition-colors ${password === ""
                                    ? "border-gray-700"
                                    : isPasswordValid
                                        ? "border-green-500"
                                        : "border-red-500"
                                }`}
                            type="password"
                            placeholder="Create a strong password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
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
                            Confirm Password
                        </label>
                        <input
                            className={`w-full bg-gray-800 border p-3 rounded text-white outline-none transition-colors ${confirmPassword === ""
                                    ? "border-gray-700"
                                    : passwordsMatch
                                        ? "border-green-500"
                                        : "border-red-500"
                                }`}
                            type="password"
                            placeholder="Confirm your password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                        />
                        {confirmPassword !== "" && !passwordsMatch && (
                            <p className="text-red-400 text-xs mt-1">Passwords do not match</p>
                        )}
                    </div>

                    <div className="bg-blue-900/20 border border-blue-800 p-3 rounded text-sm text-blue-300">
                        <p>
                            <strong>Note:</strong> All new accounts are assigned the{" "}
                            <span className="text-yellow-400 font-semibold">User</span> role,
                            which can only validate licenses.
                        </p>
                    </div>

                    <button
                        type="submit"
                        disabled={loading || !isPasswordValid || !passwordsMatch}
                        className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-bold p-3 rounded mt-2 transition-colors"
                    >
                        {loading ? "Creating Account..." : "CREATE ACCOUNT"}
                    </button>
                </form>

                <div className="mt-6 pt-4 border-t border-gray-800">
                    <Link
                        href="/"
                        className="block text-center text-sm text-gray-400 hover:text-white underline"
                    >
                        Already have an account? Login
                    </Link>
                </div>
            </div>
        </div>
    );
}
