"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

interface User {
  username: string;
  role: string;
  created_at: string;
}

export default function Dashboard() {
  const [clientName, setClientName] = useState("");
  const [generatedKey, setGeneratedKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [users, setUsers] = useState<User[]>([]);
  const [showUsers, setShowUsers] = useState(false);
  const [currentUser, setCurrentUser] = useState<{
    username: string;
    role: string;
  } | null>(null);

  const router = useRouter();

  useEffect(() => {
    // Check authentication
    const token = localStorage.getItem("token");
    const username = localStorage.getItem("username");
    const role = localStorage.getItem("role");

    if (!token) {
      router.push("/");
      return;
    }

    setCurrentUser({ username: username || "", role: role || "" });
  }, [router]);

  const getAuthHeaders = () => ({
    "Content-Type": "application/json",
    Authorization: `Bearer ${localStorage.getItem("token")}`,
  });

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/generate_license", {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ client_name: clientName }),
      });
      const data = await res.json();

      if (res.ok) {
        setGeneratedKey(data.license_key);
      } else if (res.status === 403) {
        setError(`Access Denied: ${data.message}`);
      } else {
        setError(data.error || "Failed to generate license");
      }
    } catch (err) {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  const handleViewUsers = async () => {
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/users", {
        method: "GET",
        headers: getAuthHeaders(),
      });
      const data = await res.json();

      if (res.ok) {
        setUsers(data.users);
        setShowUsers(true);
      } else if (res.status === 403) {
        setError(`Access Denied: ${data.message}`);
      } else {
        setError(data.error || "Failed to fetch users");
      }
    } catch (err) {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("role");
    router.push("/");
  };

  const isAdmin = currentUser?.role === "admin";

  return (
    <div className="min-h-screen bg-gray-950 text-white p-10 font-mono">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-2xl font-bold text-green-500">
              {isAdmin ? "ADMIN CONSOLE" : "USER DASHBOARD"}
            </h1>
            <p className="text-gray-500 text-sm">
              Logged in as: {currentUser?.username} ({currentUser?.role})
            </p>
          </div>
          <button
            onClick={handleLogout}
            className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded text-sm"
          >
            LOGOUT
          </button>
        </div>

        {/* Access Control Info */}
        <div className="mb-6 p-4 bg-gray-900 border border-gray-800 rounded">
          <h3 className="text-sm text-gray-400 mb-2">
            🔒 ACCESS CONTROL MATRIX
          </h3>
          <div className="grid grid-cols-3 gap-4 text-xs">
            <div
              className={`p-2 rounded ${isAdmin ? "bg-green-900/30 border border-green-500" : "bg-red-900/30 border border-red-500"}`}
            >
              <span className="block font-bold">Generate License</span>
              <span>{isAdmin ? "✅ Allowed" : "❌ Denied"}</span>
            </div>
            <div className="p-2 rounded bg-green-900/30 border border-green-500">
              <span className="block font-bold">Validate License</span>
              <span>✅ Allowed</span>
            </div>
            <div
              className={`p-2 rounded ${isAdmin ? "bg-green-900/30 border border-green-500" : "bg-red-900/30 border border-red-500"}`}
            >
              <span className="block font-bold">View Users</span>
              <span>{isAdmin ? "✅ Allowed" : "❌ Denied"}</span>
            </div>
          </div>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-500 text-red-300 p-4 rounded mb-6">
            {error}
          </div>
        )}

        {/* Main Content */}
        <div className="border border-gray-800 bg-gray-900 p-8 rounded-xl shadow-2xl">
          <p className="text-gray-500 text-sm mb-8">
            SECURE CONNECTION ESTABLISHED | AES-256 ENCRYPTION ACTIVE
          </p>

          {/* Generate License Section */}
          <div className="mb-8">
            <h2 className="text-lg font-bold mb-4 text-blue-400">
              Generate License
            </h2>
            <form onSubmit={handleGenerate} className="flex gap-4">
              <input
                className="flex-1 bg-black border border-gray-700 p-4 rounded text-green-400 disabled:opacity-50"
                placeholder={
                  isAdmin ? "Enter Client Name" : "Admin access required"
                }
                value={clientName}
                onChange={(e) => setClientName(e.target.value)}
                disabled={!isAdmin}
              />
              <button
                type="submit"
                disabled={loading || !isAdmin || !clientName}
                className="bg-green-600 hover:bg-green-700 disabled:bg-gray-700 text-white font-bold px-8 rounded"
              >
                {loading ? "..." : "GENERATE"}
              </button>
            </form>
            {!isAdmin && (
              <p className="text-red-400 text-xs mt-2">
                ⚠️ Only Admin role can generate licenses
              </p>
            )}
          </div>

          {/* Generated Key Display */}
          {generatedKey && (
            <div className="bg-black p-6 rounded border border-green-500/30 break-all mb-8">
              <h3 className="text-xs text-gray-500 mb-2 uppercase">
                Encrypted & Signed Token
              </h3>
              <code className="text-xs text-green-300">{generatedKey}</code>
              <div className="mt-4 flex gap-2">
                <button
                  onClick={() => navigator.clipboard.writeText(generatedKey)}
                  className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded"
                >
                  📋 Copy
                </button>
                <a
                  href="/validate"
                  className="text-xs bg-blue-700 hover:bg-blue-600 px-3 py-1 rounded"
                >
                  🔍 Validate
                </a>
              </div>
            </div>
          )}

          {/* View Users Section (Admin Only) */}
          {isAdmin && (
            <div className="mt-8 pt-8 border-t border-gray-800">
              <h2 className="text-lg font-bold mb-4 text-purple-400">
                User Management
              </h2>
              <button
                onClick={handleViewUsers}
                disabled={loading}
                className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 text-white font-bold px-6 py-2 rounded"
              >
                {loading ? "Loading..." : "VIEW ALL USERS"}
              </button>

              {showUsers && users.length > 0 && (
                <div className="mt-4 bg-black rounded border border-gray-700">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-700 text-gray-400">
                        <th className="p-3 text-left">Username</th>
                        <th className="p-3 text-left">Role</th>
                        <th className="p-3 text-left">Created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((user, i) => (
                        <tr
                          key={i}
                          className="border-b border-gray-800 hover:bg-gray-900"
                        >
                          <td className="p-3 text-green-300">{user.username}</td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-1 rounded text-xs ${user.role === "admin"
                                  ? "bg-purple-900 text-purple-300"
                                  : user.role === "user"
                                    ? "bg-blue-900 text-blue-300"
                                    : "bg-gray-700 text-gray-300"
                                }`}
                            >
                              {user.role}
                            </span>
                          </td>
                          <td className="p-3 text-gray-500">
                            {user.created_at || "N/A"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="mt-6 text-center">
          <a
            href="/validate"
            className="text-green-400 hover:underline text-sm"
          >
            Go to License Validator →
          </a>
        </div>
      </div>
    </div>
  );
}