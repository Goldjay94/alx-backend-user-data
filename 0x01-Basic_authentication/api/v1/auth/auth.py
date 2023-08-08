#!/usr/bin/env python3
"""
This module contains the authentication blueprint"""
from flask import request
from typing import List, TypeVar


class Auth():
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require_auth"""
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        if path in excluded_paths or "{}/".format(path) in excluded_paths:
            return False
        for excluded_path in excluded_paths:
            if excluded_path[-1] != '*':
                continue
            if path.startswith(excluded_path[:-1]):
                return False
        # if path[-1] != '/':
        #     path += '/'
        # if path in excluded_paths:
        #     return False
        # for excluded_path in excluded_paths:
        #     if excluded_path[-1] != '*':
        #         continue
        #     if path.startswith(excluded_path[:-1]):
        #         return False
        return True

    def authorization_header(self, request=None) -> str:
        """authorization_header"""
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """current_user"""
        return None
