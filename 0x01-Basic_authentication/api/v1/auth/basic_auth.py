#!/usr/bin/env python3
"""Module for basic authentication.
"""
from .auth import Auth
import base64


class BasicAuth(Auth):
    """Class for managing Basic authentication"""
    def extract_base64_authorization_header(
            self, authorization_header: str
            ) -> str:
        """Extracts the Base64 part of the Authorization header
        for Basic Authentication."""
        if (authorization_header is None
                or not isinstance(authorization_header, str)):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str
            ) -> str:
        """Decodes a Base64 string."""
        if (base64_authorization_header is None
                or not isinstance(base64_authorization_header, str)):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except base64.binascii.Error:
            return None

    def extract_user_credentials(
        self,
        decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extracts user credentials from the Base64 decoded value."""
        if decoded_base64_authorization_header is None or \
                not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        user_email, user_password = (
                decoded_base64_authorization_header.split(':', 1)
                )
        return (user_email, user_password)
