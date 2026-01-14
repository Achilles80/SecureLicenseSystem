"""
License Management Routes for SecureLicenseSystem

Endpoints:
- POST /license/generate - Generate license (Admin only)
- POST /license/validate - Validate license (User/Admin)
- GET /license/all - List all licenses (Admin only)
- GET /users - List all users (Admin only)
- GET /access-control-info - Get ACM documentation

Access Control:
- generate_license: Admin only
- validate_license: Admin, User, Guest
- view_users: Admin only
"""

from flask import Blueprint, request, jsonify, g
import models
from utils.crypto import create_license_token, validate_license_token
from utils.access_control import require_role, require_auth, get_access_control_info

license_bp = Blueprint('license', __name__)


@license_bp.route('/generate_license', methods=['POST'])
@require_role('generate_license')
def generate_license():
    """
    Generate a new encrypted signed license.
    
    ACCESS: Admin only
    
    Request Body:
        {
            "client_name": "string"
        }
    
    Response:
        200: License token generated
        403: Access denied for non-admin users
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    client_name = data.get('client_name', '').strip()
    
    if not client_name:
        return jsonify({"error": "Client name is required"}), 400
    
    # Generate license token (encrypts, signs, encodes)
    token = create_license_token(client_name)
    
    # Save to database for audit trail
    issued_by = g.current_user['username']
    models.save_license(
        issued_to=client_name,
        issued_by=issued_by,
        token_blob=token[:50] + "...",  # Store truncated for DB
        signature="RSA-PSS-SHA256"
    )
    
    print(f"✅ License generated for '{client_name}' by {issued_by}")
    
    return jsonify({
        "license_key": token,
        "issued_to": client_name,
        "issued_by": issued_by,
        "encryption": "AES-256-CBC",
        "signature": "RSA-PSS-SHA256",
        "encoding": "Base64"
    }), 200


@license_bp.route('/validate_license', methods=['POST'])
@require_role('validate_license')
def validate_license():
    """
    Validate a license token.
    
    ACCESS: Admin, User (anyone authenticated)
    
    This verifies:
    1. Base64 decoding is successful
    2. RSA digital signature is valid (integrity + authenticity)
    3. Data structure is correct
    
    Request Body:
        {
            "license_key": "string"
        }
    
    Response:
        200: License is valid
        400: License is invalid or tampered
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    token = data.get('license_key', '').strip()
    
    if not token:
        return jsonify({"error": "License key is required"}), 400
    
    # Validate token
    is_valid, message = validate_license_token(token)
    
    if is_valid:
        print(f"✅ License validated: {message}")
        return jsonify({
            "valid": True,
            "message": message,
            "verified_by": g.current_user['username']
        }), 200
    else:
        print(f"❌ License validation failed: {message}")
        return jsonify({
            "valid": False,
            "error": "Tampering detected",
            "message": message
        }), 400


@license_bp.route('/validate_public', methods=['POST'])
def validate_license_public():
    """
    Public license validation endpoint (no auth required).
    
    This allows anyone to verify a license without logging in.
    Useful for customers to verify their licenses.
    """
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    token = data.get('license_key', '').strip()
    
    if not token:
        return jsonify({"error": "License key is required"}), 400
    
    # Validate token
    is_valid, message = validate_license_token(token)
    
    if is_valid:
        return jsonify({
            "valid": True,
            "message": message
        }), 200
    else:
        return jsonify({
            "valid": False,
            "error": "Tampering detected",
            "message": message
        }), 400


@license_bp.route('/licenses', methods=['GET'])
@require_role('view_users')
def get_all_licenses():
    """
    Get all issued licenses.
    
    ACCESS: Admin only
    
    Response:
        200: List of all licenses
        403: Access denied for non-admin users
    """
    licenses = models.get_all_licenses()
    
    return jsonify({
        "licenses": licenses,
        "total": len(licenses)
    }), 200


@license_bp.route('/users', methods=['GET'])
@require_role('view_users')
def get_all_users():
    """
    Get all registered users.
    
    ACCESS: Admin only
    
    This demonstrates Access Control - only admins can view user list.
    
    Response:
        200: List of all users
        403: Access denied for non-admin users
    """
    users = models.get_all_users()
    
    return jsonify({
        "users": users,
        "total": len(users),
        "accessed_by": g.current_user['username']
    }), 200


@license_bp.route('/access-control', methods=['GET'])
def get_acl_info():
    """
    Get Access Control Matrix information.
    
    This endpoint is public for documentation purposes.
    Shows the ACM, role descriptions, and NIST compliance info.
    """
    return jsonify(get_access_control_info()), 200
