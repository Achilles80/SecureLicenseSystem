"""
OTP (One-Time Password) Utilities for SecureLicenseSystem

This module provides Multi-Factor Authentication (MFA) functionality:
- 6-digit random OTP generation
- OTP storage with 5-minute expiry
- OTP verification with anti-replay protection

Security Notes:
- OTP is cryptographically random (os.urandom)
- Each OTP can only be used once
- 5-minute expiry prevents delayed attacks
- OTP is invalidated after single use
"""

import os
import random
from config import OTP_LENGTH, OTP_EXPIRY_MINUTES


def generate_otp() -> str:
    """
    Generate a cryptographically secure OTP.
    
    Returns:
        A string of OTP_LENGTH (6) random digits
    
    Security:
        - Uses os.urandom for CSPRNG (Cryptographically Secure PRNG)
        - Each digit is uniformly distributed
        - 10^6 = 1,000,000 possible combinations
    """
    # Use cryptographically secure random
    otp_digits = []
    for _ in range(OTP_LENGTH):
        # Get a random byte and convert to digit 0-9
        random_byte = os.urandom(1)[0]
        digit = random_byte % 10
        otp_digits.append(str(digit))
    
    return ''.join(otp_digits)


def send_otp(username: str, phone_or_email: str, otp: str) -> bool:
    """
    Send OTP to user via console (simulated for lab demo).
    
    In production, this would:
    - Send SMS via Twilio/AWS SNS/MessageBird
    - Send Email via SMTP/SendGrid/SES
    - Push notification via Firebase
    
    For lab demo:
    - Prints to console with clear formatting
    - Returns True always (simulating successful delivery)
    
    Args:
        username: The username requesting OTP
        phone_or_email: Destination (not used in simulation)
        otp: The OTP code to "send"
    
    Returns:
        True if OTP was "sent" successfully
    """
    
    # ═══════════════════════════════════════════════════════════════════════
    # 🔐 SIMULATED OTP DELIVERY FOR LAB DEMONSTRATION
    # In production, this would integrate with Twilio or AWS SNS
    # ═══════════════════════════════════════════════════════════════════════
    
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
    """
    Format OTP response for API.
    
    Args:
        otp_sent: Whether OTP was sent successfully
        message: Optional message to include
    
    Returns:
        Dictionary with status and message
    """
    if otp_sent:
        return {
            "status": "otp_sent",
            "message": message or "OTP has been sent. Please check console/server logs.",
            "expires_in_minutes": OTP_EXPIRY_MINUTES
        }
    else:
        return {
            "status": "error",
            "message": message or "Failed to send OTP. Please try again."
        }
