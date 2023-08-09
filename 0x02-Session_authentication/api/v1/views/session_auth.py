#!/usr/bin/env python3
""" Module of Session Auth
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/logout',
                 methods=['DELETE'],
                 strict_slashes=False)
def session_logout() -> str:
    """ DELETE /api/v1/auth_session/logout
    JSON body:
    - session id
    Return:
      - Empty JSON
    """
    from api.v1.app import auth

    logout = auth.destroy_session(request)
    if not logout:
        abort(404)
    return jsonify({}), 200


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login() -> str:
    """ POST /api/v1/auth_session/login
    JSON body:
      - email
      - password
    Return:
      - User object JSON represented
    """

    user_email = request.form.get('email')
    user_pswd = request.form.get('password')

    if not user_email:
        return jsonify({"error": "email missing"}), 400
    if not user_pswd:
        return jsonify({"error": "password missing"}), 400

    try:
        search_users = User.search({'email': user_email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404
    if not search_users:
        return jsonify({"error": "no user found for this email"}), 404

    user = search_users[0]
    if not user.is_valid_password(user_pswd):
        return jsonify({"error": "wrong password"}), 401
    from api.v1.app import auth
    session_cookie = getenv("SESSION_NAME")
    session_id = auth.create_session(user.id)
    response = jsonify(user.to_json())
    response.set_cookie(session_cookie, session_id)
    return response
