#!/usr/bin/env python3
"""
Implements basic auth
"""

import base64
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
    Implementation of the basic authentication method
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts base64 encoded user and password
        from an Authorization header value
        Args:
        authorization_header (str): The HTTP Authorization header value
        Returns:
        Base64 part of the Authorization header for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.split(" ")[0] == 'Basic':
            return None
        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes a base64 string into its original form
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded = base64.b64decode(
                base64_authorization_header).decode('utf-8')
            return decoded
        except Exception as e:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Splits a email/password pair from a decoded base64 string
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        email, password = decoded_base64_authorization_header.split(":")
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Creates and returns an instance of the User class
        with given credentials
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        u = User()
        try:
            users = u.search({"email": user_email})
        except Exception:
            return None
        if len(users) <= 0:
            return None
        if not users[0].is_valid_password(user_pwd):
            return None
        return users[0]

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns the currently logged-in user object
        If no user is logged in it returns None
        """
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        basic = self.extract_base64_authorization_header(auth_header)
        decoded = self.decode_base64_authorization_header(basic)
        email, password = self.extract_user_credentials(decoded)
        user = self.user_object_from_credentials(email, password)
        return user
