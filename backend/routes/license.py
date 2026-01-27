"""
License Management Routes - handles license generation, validation, and admin operations.

Endpoints:
- POST /generate_license   - Generate encrypted+signed license (Admin only)
- POST /validate_license   - Validate license (authenticated users)
- POST /validate_public    - Public validation (no auth required)
- GET  /licenses           - List all licenses with optional filter (Admin only)
- DELETE /licenses/<id>    - Delete a license (Admin only)
- GET  /my-licenses        - Get current user's licenses
- GET  /users              - List all users (Admin only)
- GET  /access-control     - View Access Control Matrix
- GET  /audit-logs         - View audit logs (Admin only)
"""

from flask import Blueprint, request, jsonify, g
import models
from utils.crypto import create_license_token, validate_license_token
from utils.access_control import require_role, require_auth, get_access_control_info

license_bp = Blueprint('license', __name__)


@license_bp.route('/generate_license', methods=['POST'])
@require_role('generate_license')
def generate_license():
    """Generate encrypted+signed license. Admin only."""
    from datetime import datetime, timedelta
    
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    client_name = data.get('client_name', '').strip()
    expiry_days = data.get('expiry_days', 30)
    
    if not client_name:
        return jsonify({"error": "Client name is required"}), 400
    
    expires_at = datetime.now() + timedelta(days=expiry_days)
    expires_at_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")
    
    token = create_license_token(client_name)
    
    issued_by = g.current_user['username']
    license_id = models.save_license(
        issued_to=client_name,
        issued_by=issued_by,
        token_blob=token,
        signature="RSA-PSS-SHA256",
        expires_at=expires_at_str
    )
    
    models.log_audit(
        username=issued_by,
        action="LICENSE_GENERATED",
        details=f"License #{license_id} for {client_name}, expires {expires_at_str}",
        ip_address=request.remote_addr
    )
    
    print(f"[+] License generated for '{client_name}' by {issued_by} (expires: {expires_at_str})")
    
    return jsonify({
        "license_key": token,
        "issued_to": client_name,
        "issued_by": issued_by,
        "expires_at": expires_at_str,
        "encryption": "AES-256-CBC",
        "signature": "RSA-PSS-SHA256",
        "encoding": "Base64"
    }), 200


@license_bp.route('/validate_license', methods=['POST'])
@require_role('validate_license')
def validate_license():
    """Validate license token. Requires authentication."""
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    token = data.get('license_key', '').strip()
    
    if not token:
        return jsonify({"error": "License key is required"}), 400
    
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
    """Public license validation (no auth required). For customer verification."""
    data = request.json
    
    if not data:
        return jsonify({"error": "Request body required"}), 400
    
    token = data.get('license_key', '').strip()
    
    if not token:
        return jsonify({"error": "License key is required"}), 400
    
    is_valid, message = validate_license_token(token)
    
    if is_valid:
        return jsonify({"valid": True, "message": message}), 200
    else:
        return jsonify({
            "valid": False,
            "error": "Tampering detected",
            "message": message
        }), 400


@license_bp.route('/licenses', methods=['GET'])
@require_role('view_users')
def get_all_licenses():
    """Get all licenses with optional username filter. Admin only."""
    username_filter = request.args.get('username', None)
    
    if username_filter:
        licenses = models.get_licenses_filtered(username_filter)
    else:
        licenses = models.get_all_licenses()
    
    return jsonify({
        "licenses": licenses,
        "total": len(licenses),
        "filtered_by": username_filter if username_filter else None
    }), 200


@license_bp.route('/licenses/<int:license_id>', methods=['DELETE'])
@require_role('view_users')
def delete_license(license_id):
    """Delete a license by ID. Admin only."""
    deleted = models.delete_license(license_id)
    
    if deleted:
        models.log_audit(
            username=g.current_user['username'],
            action="LICENSE_DELETED",
            details=f"License #{license_id} deleted",
            ip_address=request.remote_addr
        )
        return jsonify({
            "success": True,
            "message": f"License #{license_id} deleted successfully"
        }), 200
    else:
        return jsonify({
            "success": False,
            "error": f"License #{license_id} not found"
        }), 404


@license_bp.route('/my-licenses', methods=['GET'])
@require_auth
def get_my_licenses():
    """Get licenses issued to current user."""
    username = g.current_user['username']
    licenses = models.get_user_licenses(username)
    
    return jsonify({
        "licenses": licenses,
        "total": len(licenses),
        "message": f"Licenses issued to '{username}'"
    }), 200


@license_bp.route('/users', methods=['GET'])
@require_role('view_users')
def get_all_users():
    """Get all registered users. Admin only."""
    users = models.get_all_users()
    
    return jsonify({
        "users": users,
        "total": len(users),
        "accessed_by": g.current_user['username']
    }), 200


@license_bp.route('/access-control', methods=['GET'])
def get_acl_info():
    """Get Access Control Matrix info (public endpoint for documentation)."""
    return jsonify(get_access_control_info()), 200


@license_bp.route('/audit-logs', methods=['GET'])
@require_role('view_users')
def get_audit_logs_endpoint():
    """Get audit logs for security monitoring. Admin only."""
    limit = request.args.get('limit', 100, type=int)
    logs = models.get_audit_logs(limit)
    
    return jsonify({
        "audit_logs": logs,
        "total": len(logs),
        "accessed_by": g.current_user['username']
    }), 200
