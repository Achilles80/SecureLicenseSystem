"""
Authentication Routes for SecureLicenseSystem

Endpoints:
- POST /auth/register - Create new user account
- POST /auth/login - Authenticate and receive OTP
- POST /auth/verify-otp - Complete MFA and receive JWT
- GET /auth/me - Get current user info (protected)
"""

from flask import Blueprint, request, jsonify, g
import models
from utils.crypto import hash_password, verify_password
from utils.otp import generate_otp, send_otp, format_otp_response
from utils.access_control import create_jwt_token, require_auth

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    
    Request Body:
        {
            "username": "string",
            "password": "string",
            "role": "admin|user|guest" (optional, defaults to "user")
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
    role = data.get('role', 'user').lower()
    
    # Validation
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    if role not in ['admin', 'user', 'guest']:
        return jsonify({"error": "Invalid role. Must be: admin, user, or guest"}), 400
    
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


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user (Step 1 of MFA).
    
    This verifies the password and sends an OTP for the second factor.
    
    Request Body:
        {
            "username": "string",
            "password": "string"
        }
    
    Response:
        200: OTP sent, proceed to /auth/verify-otp
        401: Invalid credentials
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Get user from database
    user = models.get_user(username)
    
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Verify password (Factor 1: Something you know)
    if not verify_password(password, user['password_hash'], user['salt']):
        return jsonify({"error": "Invalid credentials"}), 401
    
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
