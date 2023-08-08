#!/usr/bin/env python3
""" Module of Basic Auth
"""
from typing import Tuple, TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic Auth
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
           Get authorization_header then extract the value
        """
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if authorization_header.split(" ")[0] != 'Basic':
            return None
        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """
           Decoded value of a base64 authorization header
        """
        import base64
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            return base64.b64decode(
                                    base64_authorization_header
                                    ).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """Extract user credentials
        """
        if (not decoded_base64_authorization_header
                or type(decoded_base64_authorization_header) != str):
            return (None, None)
        credendials = decoded_base64_authorization_header.split(':', 1)
        return (credendials[0], credendials[1]) if ":" in\
            decoded_base64_authorization_header else (None, None)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Get User object from credentials
        """
        if not user_email or not isinstance(user_email, str)\
           or not user_pwd or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
            if not users:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ fully protected API with a Basic Authentication"""
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        base64_header = self.extract_base64_authorization_header(auth_header)
        if base64_header is None:
            return None
        decoded_header = self.decode_base64_authorization_header(base64_header)
        if decoded_header is None:
            return None
        email, pwd = self.extract_user_credentials(decoded_header)
        if email is None or pwd is None:
            return None
        return self.user_object_from_credentials(email, pwd)
