"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

interface User {
  username: string;
  role: string;
  created_at: string;
}

interface License {
  id: number;
  issued_to: string;
  issued_by: string;
  token_blob: string;
  expires_at: string;
  created_at: string;
}

interface AuditLog {
  id: number;
  timestamp: string;
  username: string;
  action: string;
  details: string;
  ip_address: string;
}

export default function Dashboard() {
  const [clientName, setClientName] = useState("");
  const [generatedKey, setGeneratedKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [users, setUsers] = useState<User[]>([]);
  const [showUsers, setShowUsers] = useState(false);
  const [myLicenses, setMyLicenses] = useState<License[]>([]);
  const [showMyLicenses, setShowMyLicenses] = useState(false);
  const [allLicenses, setAllLicenses] = useState<License[]>([]);
  const [showAllLicenses, setShowAllLicenses] = useState(false);
  const [licenseFilter, setLicenseFilter] = useState("");
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [showAuditLogs, setShowAuditLogs] = useState(false);
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

  const handleViewMyLicenses = async () => {
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/my-licenses", {
        method: "GET",
        headers: getAuthHeaders(),
      });
      const data = await res.json();

      if (res.ok) {
        setMyLicenses(data.licenses);
        setShowMyLicenses(true);
      } else {
        setError(data.error || "Failed to fetch licenses");
      }
    } catch (err) {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  const handleViewAuditLogs = async () => {
    setLoading(true);
    setError("");

    try {
      const res = await fetch("http://127.0.0.1:5000/audit-logs?limit=50", {
        method: "GET",
        headers: getAuthHeaders(),
      });
      const data = await res.json();

      if (res.ok) {
        setAuditLogs(data.audit_logs);
        setShowAuditLogs(true);
      } else {
        setError(data.error || "Failed to fetch audit logs");
      }
    } catch (err) {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  const handleViewAllLicenses = async (filterUsername?: string) => {
    setLoading(true);
    setError("");

    try {
      const url = filterUsername
        ? `http://127.0.0.1:5000/licenses?username=${encodeURIComponent(filterUsername)}`
        : "http://127.0.0.1:5000/licenses";

      const res = await fetch(url, {
        method: "GET",
        headers: getAuthHeaders(),
      });
      const data = await res.json();

      if (res.ok) {
        setAllLicenses(data.licenses);
        setShowAllLicenses(true);
      } else if (res.status === 403) {
        setError(`Access Denied: ${data.message}`);
      } else {
        setError(data.error || "Failed to fetch licenses");
      }
    } catch (err) {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteLicense = async (licenseId: number) => {
    if (!confirm(`Are you sure you want to delete license #${licenseId}?`)) {
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch(`http://127.0.0.1:5000/licenses/${licenseId}`, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });
      const data = await res.json();

      if (res.ok) {
        // Refresh the list
        handleViewAllLicenses(licenseFilter);
      } else if (res.status === 403) {
        setError(`Access Denied: ${data.message}`);
      } else {
        setError(data.error || "Failed to delete license");
      }
    } catch (err) {
      setError("Failed to connect to backend");
    } finally {
      setLoading(false);
    }
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
          <div className="grid grid-cols-4 gap-4 text-xs">
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
            <div
              className={`p-2 rounded ${isAdmin ? "bg-green-900/30 border border-green-500" : "bg-red-900/30 border border-red-500"}`}
            >
              <span className="block font-bold">View All Licenses</span>
              <span>{isAdmin ? "✅ Allowed" : "❌ Denied"}</span>
            </div>
          </div>
          {/* Quick Validate Button for All Users */}
          <div className="mt-4">
            <a
              href="/validate"
              className="inline-block bg-green-600 hover:bg-green-700 text-white text-xs font-bold px-4 py-2 rounded"
            >
              🔍 VALIDATE A TOKEN
            </a>
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
                  href={`/validate?token=${encodeURIComponent(generatedKey)}`}
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

          {/* View All Licenses Section (Admin Only) */}
          {isAdmin && (
            <div className="mt-8 pt-8 border-t border-gray-800">
              <h2 className="text-lg font-bold mb-4 text-yellow-400">
                📄 View All Licenses
              </h2>
              <p className="text-gray-500 text-xs mb-4">
                View all issued licenses. Filter by username/client name.
              </p>
              <div className="flex gap-4 items-center mb-4">
                <input
                  className="flex-1 bg-black border border-gray-700 p-3 rounded text-green-400"
                  placeholder="Filter by username (leave empty for all)"
                  value={licenseFilter}
                  onChange={(e) => setLicenseFilter(e.target.value)}
                />
                <button
                  onClick={() => handleViewAllLicenses(licenseFilter)}
                  disabled={loading}
                  className="bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-700 text-white font-bold px-6 py-2 rounded"
                >
                  {loading ? "Loading..." : "VIEW LICENSES"}
                </button>
                {licenseFilter && (
                  <button
                    onClick={() => {
                      setLicenseFilter("");
                      handleViewAllLicenses("");
                    }}
                    className="bg-gray-600 hover:bg-gray-700 text-white font-bold px-4 py-2 rounded text-sm"
                  >
                    CLEAR
                  </button>
                )}
              </div>

              {showAllLicenses && (
                <div className="mt-4">
                  <p className="text-gray-400 text-xs mb-2">
                    Showing {allLicenses.length} license(s)
                    {licenseFilter && ` matching "${licenseFilter}"`}
                  </p>
                  {allLicenses.length === 0 ? (
                    <p className="text-gray-500 text-sm">No licenses found.</p>
                  ) : (
                    <div className="bg-black rounded border border-yellow-500/30 overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="border-b border-gray-700 text-gray-400">
                            <th className="p-2 text-left">ID</th>
                            <th className="p-2 text-left">Issued To</th>
                            <th className="p-2 text-left">Issued By</th>
                            <th className="p-2 text-left">Created</th>
                            <th className="p-2 text-left">Expires</th>
                            <th className="p-2 text-left">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {allLicenses.map((license) => (
                            <tr key={license.id} className="border-b border-gray-800 hover:bg-gray-900">
                              <td className="p-2 text-gray-500">#{license.id}</td>
                              <td className="p-2 text-cyan-300">{license.issued_to}</td>
                              <td className="p-2 text-purple-300">{license.issued_by}</td>
                              <td className="p-2 text-gray-500">{license.created_at}</td>
                              <td className="p-2 text-yellow-400">{license.expires_at || "N/A"}</td>
                              <td className="p-2">
                                <div className="flex gap-2">
                                  <button
                                    onClick={() => navigator.clipboard.writeText(license.token_blob)}
                                    className="text-xs bg-gray-700 hover:bg-gray-600 px-2 py-1 rounded"
                                  >
                                    📋 Copy
                                  </button>
                                  <a
                                    href={`/validate?token=${encodeURIComponent(license.token_blob)}`}
                                    className="text-xs bg-green-700 hover:bg-green-600 px-2 py-1 rounded"
                                  >
                                    🔍 Validate
                                  </a>
                                  <button
                                    onClick={() => handleDeleteLicense(license.id)}
                                    disabled={loading}
                                    className="text-xs bg-red-700 hover:bg-red-600 disabled:bg-gray-700 px-2 py-1 rounded"
                                  >
                                    🗑️ Delete
                                  </button>
                                </div>
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
          )}

          {/* My Licenses Section (All Users) */}
          <div className="mt-8 pt-8 border-t border-gray-800">
            <h2 className="text-lg font-bold mb-4 text-cyan-400">
              🎫 My Licenses
            </h2>
            <p className="text-gray-500 text-xs mb-4">
              View licenses issued to your username. Admin generates licenses with your username as client name.
            </p>
            <button
              onClick={handleViewMyLicenses}
              disabled={loading || currentUser?.role === "guest"}
              className="bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-bold px-6 py-2 rounded"
            >
              {loading ? "Loading..." : "VIEW MY LICENSES"}
            </button>
            {currentUser?.role === "guest" && (
              <p className="text-yellow-400 text-xs mt-2">
                ⚠️ Login with a user account to view your licenses
              </p>
            )}

            {showMyLicenses && (
              <div className="mt-4">
                {myLicenses.length === 0 ? (
                  <p className="text-gray-500 text-sm">No licenses found for your username.</p>
                ) : (
                  <div className="space-y-4">
                    {myLicenses.map((license) => (
                      <div key={license.id} className="bg-black p-4 rounded border border-cyan-500/30">
                        <div className="flex justify-between items-start mb-2">
                          <div>
                            <span className="text-gray-400 text-xs">License #{license.id}</span>
                            <p className="text-cyan-300 text-sm">Issued by: {license.issued_by}</p>
                            <p className="text-gray-500 text-xs">Created: {license.created_at}</p>
                            {license.expires_at && (
                              <p className="text-yellow-400 text-xs">Expires: {license.expires_at}</p>
                            )}
                          </div>
                          <div className="flex gap-2">
                            <button
                              onClick={() => navigator.clipboard.writeText(license.token_blob)}
                              className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded"
                            >
                              📋 Copy
                            </button>
                            <a
                              href={`/validate?token=${encodeURIComponent(license.token_blob)}`}
                              className="text-xs bg-green-700 hover:bg-green-600 px-3 py-1 rounded"
                            >
                              🔍 Validate
                            </a>
                          </div>
                        </div>
                        <div className="bg-gray-900 p-2 rounded mt-2">
                          <code className="text-xs text-green-300 break-all">
                            {license.token_blob}
                          </code>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Audit Logs Section (Admin Only) */}
          {isAdmin && (
            <div className="mt-8 pt-8 border-t border-gray-800">
              <h2 className="text-lg font-bold mb-4 text-orange-400">
                📋 Audit Logs
              </h2>
              <p className="text-gray-500 text-xs mb-4">
                Security event logs for monitoring system activity.
              </p>
              <button
                onClick={handleViewAuditLogs}
                disabled={loading}
                className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-700 text-white font-bold px-6 py-2 rounded"
              >
                {loading ? "Loading..." : "VIEW AUDIT LOGS"}
              </button>

              {showAuditLogs && auditLogs.length > 0 && (
                <div className="mt-4 bg-black rounded border border-orange-500/30 overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-gray-700 text-gray-400">
                        <th className="p-2 text-left">Time</th>
                        <th className="p-2 text-left">User</th>
                        <th className="p-2 text-left">Action</th>
                        <th className="p-2 text-left">Details</th>
                        <th className="p-2 text-left">IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.map((log) => (
                        <tr key={log.id} className="border-b border-gray-800 hover:bg-gray-900">
                          <td className="p-2 text-gray-500">{log.timestamp}</td>
                          <td className="p-2 text-cyan-300">{log.username || "-"}</td>
                          <td className="p-2">
                            <span className={`px-2 py-0.5 rounded text-xs ${log.action.includes("FAILED") || log.action.includes("RATE_LIMITED")
                              ? "bg-red-900 text-red-300"
                              : log.action.includes("GENERATED")
                                ? "bg-green-900 text-green-300"
                                : "bg-blue-900 text-blue-300"
                              }`}>
                              {log.action}
                            </span>
                          </td>
                          <td className="p-2 text-gray-400">{log.details || "-"}</td>
                          <td className="p-2 text-gray-500">{log.ip_address || "-"}</td>
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