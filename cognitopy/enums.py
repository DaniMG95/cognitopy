from enum import Enum


class MessageAction(Enum):
    RESEND = "RESEND"
    SUPPRESS = "SUPPRESS"


class DesiredDelivery(Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"


class AuthFlow(Enum):
    REFRESH_TOKEN_AUTH = "REFRESH_TOKEN_AUTH"
    USER_PASSWORD_AUTH = "USER_PASSWORD_AUTH"


class AdminAuthFlow(Enum):
    REFRESH_TOKEN_AUTH = "REFRESH_TOKEN_AUTH"
    ADMIN_USER_PASSWORD_AUTH = "ADMIN_USER_PASSWORD_AUTH"


class ChallengeName(Enum):
    SMS_MFA = "SMS_MFA"
    NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED"
