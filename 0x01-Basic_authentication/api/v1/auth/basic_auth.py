#!/usr/bin/env python3
"""Module for basic authentication.
"""
from .auth import Auth


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
