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
        if not authorization_header or type(authorization_header) is not str:
            return None
        header = authorization_header.split(' ')
        return (None if not bool(re.search('^Basic ', authorization_header))
                else header[1])

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """
           Decoded value of a base64 authorization header
        """
        if (not base64_authorization_header or
                type(base64_authorization_header) != str):
            return None
        try:
            msg = base64.b64decode(base64_authorization_header.encode('utf-8'))
            return msg.decode('utf-8')
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
        try:
            header = self.authorization_header(request)
            base64header = self.extract_base64_authorization_header(header)
            decodebase64header = self.decode_base64_authorization_header(
                base64header)
            user_email, user_pwd = self.extract_user_credentials(
                decodebase64header)
            return self.user_object_from_credentials(user_email, user_pwd)
        except Exception:
            return None
