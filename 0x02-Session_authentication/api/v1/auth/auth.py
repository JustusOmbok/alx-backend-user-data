#!/usr/bin/env python3
"""Module for the API authentication.
"""
import re
from typing import List, TypeVar
from flask import request
import os


class Auth:
    """Class for managing API authentication.

    This class provides methods to handle authentication for the API.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if authentication is required for a given path.

        Args:
            path: The path of the request.
            excluded_paths: List of paths that do not require authentication.

        Returns:
            A boolean indicating whether authentication is required
            for the given path.
        """
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """Get the authorization header from the request.

        Args:
            request: The Flask request object.

        Returns:
            The value of the Authorization header field,
            or None if not present.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Get the current user from the request.

        Args:
            request: The Flask request object.

        Returns:
            The current user extracted from the request, or None.
        """
        return None

    def session_cookie(self, request=None):
        """Returns session cookies."""
        if request is None:
            return None

        session_name = os.getenv("SESSION_NAME", "_my_session_id")
        return request.cookies.get(session_name)
