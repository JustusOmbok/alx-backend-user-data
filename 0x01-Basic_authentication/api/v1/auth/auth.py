#!/usr/bin/env python3
"""Module for authentication.
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Class for managing API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if authentication is required for a given path"""

        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        # Ensure trailing slash for comparison
        path = path.rstrip('/') + '/'
        for excluded_path in excluded_paths:
            if path.startswith(excluded_path):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Get the authorization header from the request"""
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the current authenticated user from the request"""
        return None
