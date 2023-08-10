#!/usr/bin/env python3
"""DB session auth Module
"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession
import datetime


class SessionDBAuth(SessionExpAuth):
    """DB session auth class
    """
    def create_session(self, user_id=None):
        """create session overload for this subclass
        """
        session = super().create_session(user_id)
        if not session:
            return None
        data = {
                    "user_id": user_id,
                    "session_id": session
                }
        user_session = UserSession(**data)
        user_session.save()
        return session

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Get user id from a UserSession instance"""
        user_session = UserSession.search({"session_id": session_id})
        if not user_session:
            return None

        user = user_session[0]
        user_id = user.user_id
        created_at = user.created_at
        if created_at is None:
            return None
        if self.session_duration <= 0:
            return user_id
        session_expiration = created_at +\
            datetime.timedelta(seconds=self.session_duration)
        if datetime.datetime.utcnow() >= session_expiration:
            return None
        return user_id

    def destroy_session(self, request=None):
        """
        Destroy a UserSession Instance"""
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if not session_id:
            return False
        user_session = UserSession.search({"session_id": session_id})
        if user_session:
            # user_session[0].remove()
            UserSession.remove(user_session[0])
            return True
        return False
