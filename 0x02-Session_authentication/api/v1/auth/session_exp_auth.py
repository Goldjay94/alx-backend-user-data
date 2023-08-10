#!/usr/bin/env python3
"""Session Expiration Module
"""
from api.v1.auth.session_auth import SessionAuth
import os
import datetime


class SessionExpAuth(SessionAuth):
    """Class SessionExpAuth
    """
    def __init__(self) -> None:
        """Constructor"""
        try:
            duration = int(os.getenv('SESSION_DURATION'))
        except Exception:
            duration = 0
        self.session_duration = duration

    def create_session(self, user_id: str = None) -> str:
        """Creates a Session ID for a user_id"""
        session = super().create_session(user_id)
        if session is None:
            return None
        self.user_id_by_session_id[session] = {
            "user_id": user_id,
            "created_at": datetime.datetime.now()
        }

        return session

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns a User ID based on a Session ID"""
        if session_id is None:
            return None

        user_session = self.user_id_by_session_id.get(session_id)
        if user_session is None:
            return None
        user_id = user_session.get("user_id")
        created_at = user_session.get("created_at")
        if created_at is None:
            return None
        if self.session_duration <= 0:
            return user_id

        session_expiration = created_at +\
            datetime.timedelta(seconds=self.session_duration)
        if datetime.datetime.now() >= session_expiration:
            return None

        return user_id
