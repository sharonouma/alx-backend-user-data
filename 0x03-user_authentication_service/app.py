#!/usr/bin/env python3
"""
Flask app
"""

from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth


AUTH = Auth()

app = Flask(__name__)
app.url_map.strict_slashes = False


@app.route('/')
def welcome():
    """Welcome page
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    """Create a new user
    """
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            user = AUTH.register_user(email, password)
            if user:
                response = {"email": f"{email}", "message": "user created"}
                return jsonify(response)
        except ValueError:
            return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """Login to the application
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not AUTH.valid_login(email, password):
            abort(401)
        session_id = AUTH.create_session(email)
        response = jsonify({"email": f"{email}", "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response


@app.route('/sessions', methods=['DELETE'])
def logout():
    """Logout from the application
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect(url_for('welcome'))


@app.route('/profile')
def profile():
    """Display the logged-in user's profile page
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    return jsonify({"email": f"{user.email}"})


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token() -> str:
    """Reset a token for a given email address
    """
    email = request.form.get('email')
    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": f"{email}", "reset_token": f"{token}"}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """Update password with a reset token
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
        response = {"email": f"{email}", "message": "Password updated"}
        return jsonify(response), 200
    except ValueError:
        abort(403)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
