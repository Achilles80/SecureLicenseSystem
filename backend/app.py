"""
SecureLicenseSystem - Main Application Entry Point

This application demonstrates core security concepts:
1. Authentication (Single-Factor + Multi-Factor)
2. Authorization (Role-Based Access Control)
3. Encryption (AES-256 + RSA-2048)
4. Hashing & Digital Signatures (PBKDF2 + RSA-PSS)
5. Encoding (Base64)

"""

from flask import Flask
from flask_cors import CORS

# Import route blueprints
from routes.auth import auth_bp
from routes.license import license_bp

# Import database setup
import models

def create_app():
    """Application factory for Flask app."""
    app = Flask(__name__)
    
    # Enable CORS for frontend communication
    CORS(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(license_bp)
    
    return app


def main():
    """Main entry point."""
    
    print("\n" + "=" * 70)
    print("  SecureLicenseSystem - Cyber Security Lab Demonstration")
    print("=" * 70)
    print("  ✅ RSA-2048 Keys Generated")
    print("  ✅ AES-256 Key Generated")
    print("=" * 70)
    
    # Initialize database
    models.init_db()
    
    # Seed default users for demo
    print("\n📋 Seeding default users...")
    models.seed_default_users()
    
    print("\n" + "-" * 70)
    print("  DEFAULT TEST ACCOUNTS (pre-seeded)")
    print("-" * 70)
    print("  | Username  | Password   | Role   | Permissions              |")
    print("  |-----------|------------|--------|--------------------------|")
    print("  | admin     | admin123   | admin  | All (generate, validate) |")
    print("  | user      | user123    | user   | Validate only            |")
    print("  | guest     | guest123   | guest  | Validate only            |")
    print("-" * 70)
    
    print("\n📡 API Endpoints:")
    print("  POST /auth/register    - Register new user")
    print("  POST /auth/login       - Login (get OTP)")
    print("  POST /auth/verify-otp  - Complete MFA (get JWT)")
    print("  GET  /auth/me          - Current user info")
    print("  POST /generate_license - Generate license (Admin only)")
    print("  POST /validate_license - Validate license")
    print("  POST /validate_public  - Public validation (no auth)")
    print("  GET  /users            - List users (Admin only)")
    print("  GET  /access-control   - View Access Control Matrix")
    print("-" * 70)
    
    # Create and run app
    app = create_app()
    
    print("\n  Starting server on http://127.0.0.1:5000")
    print("=" * 70 + "\n")
    
    app.run(debug=True, port=5000)


if __name__ == '__main__':
    main()