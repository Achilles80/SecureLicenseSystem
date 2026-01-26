"""
Authentication Routes for SecureLicenseSystem

Endpoints:
- POST /auth/register - Create new user account
- POST /auth/login - Authenticate and receive OTP
- POST /auth/verify-otp - Complete MFA and receive JWT
- POST /auth/guest-login - Quick guest login (no MFA)
- GET /auth/me - Get current user info (protected)
"""

from flask import Blueprint, request, jsonify, g
import re
import models
from utils.crypto import hash_password, verify_password
from utils.otp import generate_otp, send_otp, format_otp_response
from utils.access_control import create_jwt_token, require_auth

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def validate_password(password: str) -> tuple[bool, list[str]]:
    """
    Validate password against security policy.
    
    Policy Requirements:
    - Minimum 8 characters
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
    
    Returns:
        (is_valid, list of unmet requirements)
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter (A-Z)")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter (a-z)")
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)")
    
    return (len(errors) == 0, errors)


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    
    SECURITY: Only 'user' role is allowed for registration.
    Admin accounts must be created via database seeding.
    
    Password Policy:
    - Minimum 8 characters
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one special character
    
    Request Body:
        {
            "username": "string",
            "password": "string"
        }
    
    Response:
        201: User registered successfully
        400: User already exists or validation error
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # SECURITY: Always assign 'user' role - ignore any role parameter
    # This prevents privilege escalation attacks
    role = "user"
    
    # Validation
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    # Enforce strong password policy
    is_valid, password_errors = validate_password(password)
    if not is_valid:
        return jsonify({
            "error": "Password does not meet security requirements",
            "password_errors": password_errors
        }), 400
    
    # Hash password with salt
    password_hash, salt = hash_password(password)
    
    # Create user
    if models.create_user(username, password_hash, salt, role):
        print(f"✅ New user registered: {username} (role: {role})")
        return jsonify({
            "message": "User registered successfully",
            "username": username,
            "role": role
        }), 201
    else:
        return jsonify({"error": "Username already exists"}), 400


@auth_bp.route('/guest-login', methods=['POST'])
def guest_login():
    """
    Quick guest login without MFA.
    
    This allows demonstration of RBAC - guest can only validate licenses.
    No password required - just issues a guest token directly.
    
    Response:
        200: JWT token for guest access
    """
    # Check if guest user exists
    guest_user = models.get_user('guest')
    
    if not guest_user:
        return jsonify({"error": "Guest account not configured"}), 500
    
    # Issue JWT token directly (skip MFA for demo)
    token = create_jwt_token('guest', 'guest')
    
    print("✅ Guest login successful (MFA bypassed for demo)")
    
    return jsonify({
        "message": "Logged in as guest",
        "token": token,
        "username": "guest",
        "role": "guest",
        "note": "Guest can only validate licenses, not generate"
    }), 200


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user (Step 1 of MFA) with rate limiting.
    
    Request Body:
        {"username": "string", "password": "string"}
    
    Response:
        200: OTP sent
        401: Invalid credentials
        429: Rate limited (too many failed attempts)
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    ip_address = request.remote_addr
    
    # Rate Limiting: Check if too many failed attempts
    if models.is_rate_limited(username):
        models.log_audit(username, "LOGIN_RATE_LIMITED", "Too many failed attempts", ip_address)
        return jsonify({
            "error": "Too many failed login attempts",
            "message": "Please wait 15 minutes before trying again"
        }), 429
    
    # Get user from database
    user = models.get_user(username)
    
    if not user:
        models.record_login_attempt(username, success=False, ip_address=ip_address)
        models.log_audit(username, "LOGIN_FAILED", "User not found", ip_address)
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Verify password (Factor 1: Something you know)
    if not verify_password(password, user['password_hash'], user['salt']):
        models.record_login_attempt(username, success=False, ip_address=ip_address)
        models.log_audit(username, "LOGIN_FAILED", "Invalid password", ip_address)
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Success - record attempt and log
    models.record_login_attempt(username, success=True, ip_address=ip_address)
    models.log_audit(username, "LOGIN_PASSWORD_OK", "Password verified, OTP sent", ip_address)
    
    # Generate OTP (Factor 2: Something you have)
    otp = generate_otp()
    
    # Store OTP in database
    models.create_otp(username, otp)
    
    # Send OTP (simulated - prints to console)
    send_otp(username, f"+91-XXX-XXX-{username[-4:]}", otp)
    
    return jsonify({
        "message": "Password verified. OTP has been sent.",
        "mfa_required": True,
        "username": username,
        "role": user['role'],
        "next_step": "POST /auth/verify-otp with username and otp"
    }), 200


@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp_endpoint():
    """
    Verify OTP (Step 2 of MFA) and issue JWT token.
    
    Request Body:
        {
            "username": "string",
            "otp": "string"
        }
    
    Response:
        200: JWT token issued
        401: Invalid or expired OTP
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    username = data.get('username', '').strip()
    otp = data.get('otp', '').strip()
    
    if not username or not otp:
        return jsonify({"error": "Username and OTP are required"}), 400
    
    # Verify OTP
    if not models.verify_otp(username, otp):
        return jsonify({
            "error": "Invalid or expired OTP",
            "message": "Please request a new OTP"
        }), 401
    
    # Get user role for token
    user = models.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Issue JWT token
    token = create_jwt_token(username, user['role'])
    
    print(f"✅ MFA completed for user: {username}")
    
    return jsonify({
        "message": "Authentication successful",
        "token": token,
        "username": username,
        "role": user['role']
    }), 200


@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user_info():
    """
    Get current authenticated user info.
    
    Requires: Bearer token in Authorization header
    
    Response:
        200: User info
        401: Not authenticated
    """
    user = g.current_user
    
    return jsonify({
        "username": user['username'],
        "role": user['role'],
        "authenticated": True
    }), 200


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """
    Request a password reset OTP.
    
    This sends an OTP to the terminal (simulated SMS/email).
    
    Request Body:
        {
            "username": "string"
        }
    
    Response:
        200: OTP sent successfully
        404: User not found
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    username = data.get('username', '').strip()
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    # Check if user exists
    user = models.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Generate OTP for password reset
    otp = generate_otp()
    
    # Store OTP in database
    models.create_otp(username, otp)
    
    # Send OTP (simulated - prints to console)
    print("\n" + "=" * 50)
    print("🔐 PASSWORD RESET OTP")
    print("=" * 50)
    print(f"   User: {username}")
    print(f"   OTP:  {otp}")
    print(f"   Expires in 5 minutes")
    print("=" * 50 + "\n")
    
    return jsonify({
        "message": "Password reset OTP has been sent",
        "username": username,
        "next_step": "POST /auth/reset-password with username, otp, and new_password"
    }), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Reset password using OTP verification.
    
    Password Policy:
    - Minimum 8 characters
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one special character
    
    Request Body:
        {
            "username": "string",
            "otp": "string",
            "new_password": "string"
        }
    
    Response:
        200: Password reset successful
        400: Validation error or invalid OTP
        404: User not found
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    username = data.get('username', '').strip()
    otp = data.get('otp', '').strip()
    new_password = data.get('new_password', '')
    
    if not username or not otp or not new_password:
        return jsonify({"error": "Username, OTP, and new password are required"}), 400
    
    # Check if user exists
    user = models.get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Verify OTP
    if not models.verify_otp(username, otp):
        return jsonify({
            "error": "Invalid or expired OTP",
            "message": "Please request a new password reset OTP"
        }), 400
    
    # Enforce strong password policy
    is_valid, password_errors = validate_password(new_password)
    if not is_valid:
        return jsonify({
            "error": "Password does not meet security requirements",
            "password_errors": password_errors
        }), 400
    
    # Hash new password with salt
    password_hash, salt = hash_password(new_password)
    
    # Update password in database
    if models.update_user_password(username, password_hash, salt):
        print(f"✅ Password reset successful for user: {username}")
        return jsonify({
            "message": "Password has been reset successfully",
            "username": username
        }), 200
    else:
        return jsonify({"error": "Failed to update password"}), 500
