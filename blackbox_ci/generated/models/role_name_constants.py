from enum import Enum


class RoleNameConstants(str, Enum):
    ADMIN = 'admin'
    AUDITOR = 'auditor'
    BASIC_API_TOKEN = 'basic_api_token'
    BASIC_UNREGISTERED_USER = 'basic_unregistered_user'
    BASIC_UNVERIFIED_USER = 'basic_unverified_user'
    BASIC_VERIFIED_USER = 'basic_verified_user'
    GUEST = 'guest'
    MANAGER = 'manager'
    MODERATOR = 'moderator'
    OPERATOR = 'operator'
    SERVICE_API_TOKEN = 'service_api_token'

    def __str__(self) -> str:
        return str(self.value)
