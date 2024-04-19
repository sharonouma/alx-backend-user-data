#!/usr/bin/env python3
"""
A Flask view that handles all routes for the Session authentication
"""

import os
from api.v1.views import app_views
from models.user import User
from flask import abort, jsonify, request


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """Logs a user into the system and returns an auth token."""
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None or email == '':
        return jsonify({"error": "email missing"}), 400
    if password is None or password == '':
        return jsonify({"error": "password missing"}), 400
    try:
        user = User.search({"email": email})
    except Exception:
        return None
    if len(user) <= 0:
        return jsonify({"error": "no user found for this email"}), 404
    if not user[0].is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401
    from api.v1.app import auth
    session_id = auth.create_session(user[0].id)
    res = jsonify(user[0].to_json())
    res.set_cookie(os.getenv("SESSION_NAME"), session_id)
    return res


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
    """Removes the current logged in users session id cookie."""
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
