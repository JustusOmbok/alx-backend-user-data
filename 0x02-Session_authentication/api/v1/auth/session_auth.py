#!/usr/bin/env python3
"""Module  for creating session authentication.
"""
from .auth import Auth
import uuid
import os
from models.user import User


class SessionAuth(Auth):
    """Create a class SessionAuth that inherits from Auth.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Method to create session id from user id."""
        if user_id is None or not isinstance(user_id, str):
            return None

        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Function to retreave user id by session id."""
        if session_id is None or not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)

    def session_cookie(self, request=None):
        """Function that returns session cookies."""
        if request is None:
            return None
        return request.cookies.get(os.getenv("SESSION_NAME"))

    def current_user(self, request=None):
        """Returns current user session id."""
        if request is None:
            return None
        session_id = self.session_cookie(request)
        if session_id:
            user_id = self.user_id_for_session_id(session_id)
            if user_id:
                return User.get(user_id)
        return None
