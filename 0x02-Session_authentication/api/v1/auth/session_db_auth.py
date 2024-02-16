#!/usr/bin/env python3
"""Module session authentication db.
"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from datetime import datetime, timedelta
import uuid
from flask import request


class SessionDBAuth(SessionExpAuth):
    """Session authentication with session IDs stored in the database."""
    def create_session(self, user_id=None):
        """Create a new session and store it in the database."""
        session_id = super().create_session(user_id)
        if session_id is None:
            return None

        session = UserSession(
            user_id=user_id,
            session_id=session_id,
            created_at=datetime.now()
        )
        session.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Retrieve the user ID associated
        with a session ID from the database."""
        if session_id is None:
            return None

        session = UserSession.search({'session_id': session_id})
        if not session:
            return None

        return session[0].user_id

    def destroy_session(self, request=None):
        """Function to destroy session."""
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        session = UserSession.search({'session_id': session_id})
        if not session:
            return False

        session[0].remove()
        return True
