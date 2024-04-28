#!/usr/bin/env python3
"""
auth module
"""
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
import uuid


def _hash_password(password: str) -> bytes:
    """
    Hash a password using the bcrypt algorithm
    :param password: The plain text password to hash.
    :return: A byte string of the hashed password.
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def _generate_uuid() -> str:
    """
    Generates a unique UUID.
    Returns:
    A string representation of a UUID4.
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """
        Constructs an instance of the Auth class.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user in the users table and returns it.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                raise ValueError("User {} already exists.".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(
                email=email, hashed_password=hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks whether login credentials are correct or not.
        Args:
        email (str): The email address of the user attempting to log in.
        password (str): The password provided by the user.
        Returns:
        True if the login is successful, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                return bcrypt.checkpw(
                    password.encode('utf-8'), user.hashed_password)
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """Creates a session token for a given user's email.
        Args:
        email (str): The email address of the user logging in.
        Returns:
        A new session token as a string.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                session_id = _generate_uuid()
                self._db.update_user(user.id, session_id=session_id)
                return session_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> User or None:
        """Retrieves the user associated with a given session ID.
        Args:
        session_id (str): The unique identifier for the user's session.
        Returns:
        The user object associated with the session ID, or None if no
        matching user was found.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Removes the session ID from the database for a specified user.
        Args:
        user_id (int): The unique identifier for the user
                        whose session will be destroyed.
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generate and store a password reset token for a user.
        """
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Update the user's password using a previously generated reset token.
        If an invalid token is provided, this method raises a ValueError.
        Args:
        reset_token: A string that represents the password reset token.
        password:   A string containing the new password.
        Raises:
        ValueError: If the provided token does not match any known tokens
        in the system.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(
                user.id, hashed_password=hashed_password, reset_token=None)
        except Exception:
            raise ValueError
