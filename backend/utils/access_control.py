"""
Access Control Module - Implements Role-Based Access Control (RBAC).

Features:
- JWT token management for stateless authentication
- Access Control Matrix for permission checks
- Route decorators (@require_auth, @require_role)

Roles: admin (full access), user (validate only), guest (validate only)
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


# JWT Token Management

def create_jwt_token(username: str, role: str) -> str:
    """Create a signed JWT token with 24h expiry."""
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises error if expired/invalid."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def get_current_user():
    """Extract current user from Authorization header. Returns None if invalid."""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    
    try:
        payload = decode_jwt_token(token)
        return {"username": payload["sub"], "role": payload["role"]}
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# Access Control Decorators

def check_permission(role: str, resource: str) -> bool:
    """Check if role has permission to access resource in the ACM."""
    if role not in ACCESS_CONTROL_MATRIX:
        return False
    return ACCESS_CONTROL_MATRIX[role].get(resource, False)


def require_auth(f):
    """Decorator: Requires valid JWT token. Sets g.current_user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({
                "error": "Unauthorized",
                "message": "Valid authentication token required"
            }), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_role(resource: str):
    """
    Decorator factory: Requires specific permission from ACM.
    Usage: @require_role('generate_license')
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
            
            if not check_permission(user['role'], resource):
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Access denied. Role '{user['role']}' cannot access '{resource}'",
                    "required_permission": resource,
                    "your_role": user['role']
                }), 403
            
            g.current_user = user
            return f(*args, **kwargs)
        return decorated
    return decorator


# Access Control Info

def get_access_control_info() -> dict:
    """Return ACM documentation for API endpoint."""
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
                "description": "Minimal access user",
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
