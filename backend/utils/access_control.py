"""
Access Control Module for SecureLicenseSystem

This module implements Role-Based Access Control (RBAC) following 
NIST SP 800-63-2 E-Authentication Architecture Model.

Components:
1. Access Control Matrix - defines who can access what
2. JWT Token management - stateless authentication
3. Role decorators - protect Flask routes

Access Control Matrix:
┌─────────┬──────────────────┬──────────────────┬────────────┐
│ Role    │ generate_license │ validate_license │ view_users │
├─────────┼──────────────────┼──────────────────┼────────────┤
│ Admin   │ ✅ ALLOWED       │ ✅ ALLOWED       │ ✅ ALLOWED │
│ User    │ ❌ DENIED        │ ✅ ALLOWED       │ ❌ DENIED  │
│ Guest   │ ❌ DENIED        │ ✅ ALLOWED       │ ❌ DENIED  │
└─────────┴──────────────────┴──────────────────┴────────────┘

Policy Justification:
- Admin: System administrators who manage licenses and users
- User: Regular authenticated users who can only validate licenses
- Guest: Limited access for public validation only
"""

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g

from config import (
    ACCESS_CONTROL_MATRIX, 
    JWT_SECRET, 
    JWT_ALGORITHM, 
    JWT_EXPIRY_HOURS
)


# =============================================================================
# JWT TOKEN MANAGEMENT
# =============================================================================

def create_jwt_token(username: str, role: str) -> str:
    """
    Create a JWT token for authenticated user.
    
    Args:
        username: The authenticated username
        role: The user's role (admin, user, guest)
    
    Returns:
        Encoded JWT token string
    
    Security:
        - Token expires after JWT_EXPIRY_HOURS (24h)
        - Signed with HS256 using JWT_SECRET
        - Contains role for authorization checks
    """
    payload = {
        "sub": username,  # Subject (who the token is for)
        "role": role,     # Role for RBAC
        "iat": datetime.utcnow(),  # Issued at
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)  # Expiry
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_jwt_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    
    Args:
        token: The JWT token string
    
    Returns:
        Decoded payload dictionary
    
    Raises:
        jwt.ExpiredSignatureError: If token is expired
        jwt.InvalidTokenError: If token is invalid
    """
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    return payload


def get_current_user():
    """
    Get the current user from the request's JWT token.
    
    Returns:
        Dict with username and role, or None if not authenticated
    """
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    
    try:
        payload = decode_jwt_token(token)
        return {
            "username": payload["sub"],
            "role": payload["role"]
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# =============================================================================
# ACCESS CONTROL DECORATORS
# =============================================================================

def check_permission(role: str, resource: str) -> bool:
    """
    Check if a role has permission to access a resource.
    
    Args:
        role: The user's role
        resource: The resource/action being accessed
    
    Returns:
        True if allowed, False if denied
    """
    if role not in ACCESS_CONTROL_MATRIX:
        return False
    
    role_permissions = ACCESS_CONTROL_MATRIX[role]
    return role_permissions.get(resource, False)


def require_auth(f):
    """
    Decorator to require authentication for a route.
    
    Usage:
        @app.route('/protected')
        @require_auth
        def protected_route():
            user = g.current_user  # Access current user
            return jsonify({"message": f"Hello {user['username']}"})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        
        if not user:
            return jsonify({
                "error": "Unauthorized",
                "message": "Valid authentication token required"
            }), 401
        
        # Store user in Flask's g object for route access
        g.current_user = user
        
        return f(*args, **kwargs)
    
    return decorated


def require_role(resource: str):
    """
    Decorator factory to require specific permission for a route.
    
    This checks the Access Control Matrix to verify the user's role
    has permission to access the specified resource.
    
    Usage:
        @app.route('/admin/generate')
        @require_role('generate_license')
        def generate():
            # Only admins can reach here
            return jsonify({"message": "License generated"})
    
    Args:
        resource: The resource name in the Access Control Matrix
    
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            
            if not user:
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Valid authentication token required"
                }), 401
            
            # Check Access Control Matrix
            if not check_permission(user['role'], resource):
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Access denied. Role '{user['role']}' cannot access '{resource}'",
                    "required_permission": resource,
                    "your_role": user['role']
                }), 403
            
            # Store user in Flask's g object
            g.current_user = user
            
            return f(*args, **kwargs)
        
        return decorated
    
    return decorator


# =============================================================================
# ACCESS CONTROL INFORMATION ENDPOINTS DATA
# =============================================================================

def get_access_control_info() -> dict:
    """
    Get information about the access control system for documentation.
    
    Returns:
        Dictionary with ACM and role descriptions
    """
    return {
        "access_control_matrix": ACCESS_CONTROL_MATRIX,
        "roles": {
            "admin": {
                "description": "System administrator with full access",
                "permissions": ["Generate licenses", "Validate licenses", "View users"]
            },
            "user": {
                "description": "Regular authenticated user",
                "permissions": ["Validate licenses only"]
            },
            "guest": {
                "description": "Unauthenticated or minimal access user",
                "permissions": ["Validate licenses only"]
            }
        },
        "resources": {
            "generate_license": "Create new encrypted signed licenses",
            "validate_license": "Verify license authenticity",
            "view_users": "View all registered users"
        },
        "nist_compliance": "NIST SP 800-63-2 E-Authentication Architecture Model"
    }
