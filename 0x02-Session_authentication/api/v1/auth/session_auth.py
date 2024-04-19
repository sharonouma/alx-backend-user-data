#!/usr/bin/env python3
"""
Implements session authentication
"""

import uuid

from flask import abort, jsonify
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Session Authentication Class."""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create a new API session for the given user ID and return its
        unique identifier (UUID string)
        Args:
        user_id: The user's unique identifier. Defaults to `None`.
        Returns:
        A UUID string representing the newly-created session's
        unique identifier.
        """
        if user_id is None:
            return None
        if not isinstance(user_id, str):
            return None
        unique_id = str(uuid.uuid4())
        self.user_id_by_session_id[unique_id] = user_id
        return unique_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Return the user ID associated with the provided session ID. If no
        such session exists or if an invalid argument was passed,returns `None`
        Args:
        session_id: The session's unique identifier.
        Returns:
        The user's unique identifier associated with the session.
        """
        if session_id is None:
            return None
        if not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Get the currently logged in user from the request object.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """
        Clear the session cookie and remove any association between a
        user and a session.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if request is None or session_id is None:
            return False
        if user_id is None:
            return False
        del self.user_id_by_session_id[session_id]
        return True
