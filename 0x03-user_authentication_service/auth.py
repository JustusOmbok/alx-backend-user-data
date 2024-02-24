#!/usr/bin/env python3
"""auth module
"""
import bcrypt
from db import DB
from user import User
import uuid
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def _generate_uuid() -> str:
    """Generate a new UUID"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Check if login credentials are valid"""
        try:
            user = self._db.find_user_by(email=email)
            if user and bcrypt.checkpw(
                    password.encode(),
                    user.hashed_password):
                return True
        except NoResultFound:
            pass
        return False

    def create_session(self, email: str) -> str:
        """Create a new session for the user"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                session_id = _generate_uuid()
                user.session_id = session_id
                self._db._session.commit()
                return session_id
        except NoResultFound:
            pass
        return None

    def get_user_from_session_id(self, session_id: str):
        """Get user from session ID"""
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy session for the user"""
        user = self._db.find_user_by(id=user_id)
        if user:
            user.session_id = None
            self._db._session.commit()

    def get_reset_password_token(self, email: str) -> str:
        """Generate reset password token for the user"""
        user = self._db.find_user_by(email=email)
        if not user:
            raise ValueError(f"User does not exist.")

        reset_token = str(uuid.uuid4())
        user.reset_token = reset_token
        self._db._session.commit()

        return reset_token
