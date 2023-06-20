from enum import Enum


class MessageAction(Enum):
    RESEND = "RESEND"
    SUPPRESS = "SUPPRESS"


class DesiredDelivery(Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
