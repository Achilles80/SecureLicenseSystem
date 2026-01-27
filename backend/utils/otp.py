"""
OTP (One-Time Password) Utilities for Multi-Factor Authentication.

- Generates 6-digit cryptographically secure OTPs
- 5-minute expiry with single-use protection
- Simulated delivery via console (production would use SMS/Email)
"""

import os
from config import OTP_LENGTH, OTP_EXPIRY_MINUTES


def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP using os.urandom."""
    otp_digits = []
    for _ in range(OTP_LENGTH):
        random_byte = os.urandom(1)[0]
        otp_digits.append(str(random_byte % 10))
    return ''.join(otp_digits)


def send_otp(username: str, phone_or_email: str, otp: str) -> bool:
    """
    Send OTP to user (simulated via console for demo).
    In production: integrate with Twilio/AWS SNS for SMS or SendGrid for email.
    """
    print("\n" + "=" * 60)
    print("📱 MULTI-FACTOR AUTHENTICATION - OTP DELIVERY")
    print("=" * 60)
    print(f"  Username:     {username}")
    print(f"  Destination:  {phone_or_email or 'Console (Demo Mode)'}")
    print(f"  OTP Code:     🔑 {otp}")
    print(f"  Expires in:   {OTP_EXPIRY_MINUTES} minutes")
    print("=" * 60)
    print("⚠️  In production, this OTP would be sent via SMS/Email")
    print("=" * 60 + "\n")
    return True


def format_otp_response(otp_sent: bool, message: str = None) -> dict:
    """Format OTP API response."""
    if otp_sent:
        return {
            "status": "otp_sent",
            "message": message or "OTP has been sent. Please check console/server logs.",
            "expires_in_minutes": OTP_EXPIRY_MINUTES
        }
    return {
        "status": "error",
        "message": message or "Failed to send OTP. Please try again."
    }
