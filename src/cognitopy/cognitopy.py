from botocore.exceptions import ClientError, EndpointConnectionError
import boto3
import hmac
import hashlib
import base64
from datetime import datetime
from jose import jwt, JWTError
from .exceptions import (
    ExceptionJWTCognito,
    ExceptionAuthCognito,
    ExceptionConnectionCognito,
    ExceptionTokenExpired,
)


class CognitoPy:
    __SERVICE_NAME = "cognito-idp"
    __FORMAT = "utf-8"
    __AUTHENTICATION_RESULT = "AuthenticationResult"
    __ACCESS_TOKEN = "AccessToken"
    __REFRESH_TOKEN = "RefreshToken"
    __ACCESS_TOKEN_KEY = "access_token"
    __REFRESH_TOKEN_KEY = "refresh_token"
    __ERROR = "Error"
    __MESSAGE = "Message"
    __SECRET_HASH = "SECRET_HASH"
    __USERNAME = "USERNAME"
    __PASSWORD = "PASSWORD"
    __REFRESH_TOKEN_AUTH = "REFRESH_TOKEN_AUTH"
    __USER_PASSWORD_AUTH = "USER_PASSWORD_AUTH"
    __GROUPS = "groups"
    __GROUP_KEY = "cognito:groups"

    def __init__(self, userpool_id: str, client_id: str, client_secret: str):
        if not isinstance(userpool_id, str) or not isinstance(client_id, str) or not isinstance(client_secret, str):
            raise ValueError("The userpool_id, client_id and client_secret should be strings")
        if "_" in userpool_id:
            self.__region_name = userpool_id.split("_")[0]
        else:
            raise ValueError("The format userpool_id is incorrect")
        self.__userpool_id = userpool_id
        self.__client_id = client_id
        self.__client_secret = client_secret

    @property
    def userpool_id(self):
        return self.__userpool_id

    @property
    def client_id(self):
        return self.__client_id

    @property
    def client_secret(self):
        return self.__client_secret

    @property
    def region_name(self):
        return self.__region_name

    @property
    def __client(self):
        try:
            client = boto3.client(self.__SERVICE_NAME, region_name=self.__region_name)
        except EndpointConnectionError as e:
            raise ExceptionConnectionCognito(str(e))
        else:
            return client

    def __get_secret_hash(self, username: str) -> str:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        key = bytes(self.__client_secret, self.__FORMAT)
        message = bytes(f"{username}{self.__client_id}", self.__FORMAT)
        dig = hmac.new(key=key, msg=message, digestmod=hashlib.sha256).digest()
        return base64.b64encode(dig).decode()

    @staticmethod
    def __dict_to_cognito(attributes: dict) -> list[dict]:
        if not isinstance(attributes, dict):
            raise ValueError("The attributes should be a dict.")
        return [
            {"Name": key, "Value": str(value).lower() if isinstance(value, bool) else value}
            for key, value in attributes.items()
        ]

    @staticmethod
    def check_expired_token(access_token: str) -> bool:
        if not isinstance(access_token, str):
            raise ValueError("The access_token should be a string.")
        now = datetime.now()
        try:
            dec_access_token = jwt.get_unverified_claims(token=access_token)
        except JWTError:
            raise ExceptionJWTCognito("Error decoding token claims.")
        if now > datetime.fromtimestamp(dec_access_token["exp"]):
            expired = True
        else:
            expired = False
        return expired

    def renew_access_token(self, access_token: str, refresh_token: str) -> dict:
        if not isinstance(access_token, str) or not isinstance(refresh_token, str):
            raise ValueError("The access_token and refresh_token should be strings.")
        username = self.get_info_user_by_token(access_token=access_token)[self.__USERNAME.lower()]
        try:
            response = self.__client.initiate_auth(
                ClientId=self.__client_id,
                AuthFlow=self.__REFRESH_TOKEN_AUTH,
                AuthParameters={
                    self.__REFRESH_TOKEN_KEY.upper(): refresh_token,
                    self.__SECRET_HASH: self.__get_secret_hash(username=username),
                },
            )
            return response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN]

        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def login(self, username: str, password: str) -> dict:
        if not isinstance(username, str) or not isinstance(password, str):
            raise ValueError("The username and password should be strings.")
        try:
            response = self.__client.initiate_auth(
                AuthFlow=self.__USER_PASSWORD_AUTH,
                ClientId=self.__client_id,
                AuthParameters={
                    self.__USERNAME: username,
                    self.__PASSWORD: password,
                    self.__SECRET_HASH: self.__get_secret_hash(username=username),
                },
            )
            return {
                self.__ACCESS_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN],
                self.__REFRESH_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__REFRESH_TOKEN],
            }
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def register(self, username: str, user_attributes: dict, password: str) -> None:
        if not isinstance(username, str) or not isinstance(user_attributes, dict) or not isinstance(password, str):
            raise ValueError("The username, password should be strings and user_attributes should be a dict.")
        cognito_attributes = self.__dict_to_cognito(user_attributes)
        try:
            self.__client.sign_up(
                ClientId=self.__client_id,
                Username=username,
                Password=password,
                UserAttributes=cognito_attributes,
                SecretHash=self.__get_secret_hash(username=username),
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def resend_confirmation_code(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            self.__client.resend_confirmation_code(ClientId=self.__client_id, Username=username)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def confirm_sing_up(self, username: str, confirmation_code: str) -> None:
        if not isinstance(username, str) or not isinstance(confirmation_code, str):
            raise ValueError("The username and confirmation_code should be strings.")
        try:
            self.__client.confirm_sign_up(
                ClientId=self.__client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                SecretHash=self.__get_secret_hash(username=username),
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def initiate_forgot_password(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            self.__client.forgot_password(
                ClientId=self.__client_id, Username=username, SecretHash=self.__get_secret_hash(username=username)
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def delete_user(self, access_token: str) -> None:
        if not isinstance(access_token, str):
            raise ValueError("The access_token should be a string.")
        if self.check_expired_token(access_token=access_token):
            raise ExceptionTokenExpired("Token expired")
        try:
            self.__client.delete_user(AccessToken=access_token)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def confirm_forgot_password(self, username: str, confirmation_code: str, password: str) -> None:
        if not isinstance(username, str) or not isinstance(confirmation_code, str) or not isinstance(password, str):
            raise ValueError("The username, confirmation_code and password should be strings.")
        try:
            self.__client.confirm_forgot_password(
                ClientId=self.__client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=password,
                SecretHash=self.__get_secret_hash(username=username),
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def change_password(self, previous_password: str, proposed_password: str, access_token: str) -> None:
        if (
            not isinstance(previous_password, str)
            or not isinstance(proposed_password, str)
            or not isinstance(access_token, str)
        ):
            raise ValueError("The previous_password, proposed_password and access_token should be strings.")
        if self.check_expired_token(access_token=access_token):
            raise ExceptionTokenExpired("Token expired")
        try:
            self.__client.change_password(
                PreviousPassword=previous_password, ProposedPassword=proposed_password, AccessToken=access_token
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_delete_user(self, username) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            self.__client.admin_delete_user(UserPoolId=self.__userpool_id, Username=username)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_create_group(self, group_name: str, description: str, precedence: int, role_arn: str = None) -> None:
        if not isinstance(group_name, str) or not isinstance(description, str) or not isinstance(precedence, int):
            raise ValueError(
                "The group_name, description and role arm should be strings" " and precedence should be an integer."
            )
        param_role = {"RoleArn": role_arn} if role_arn else {}
        try:
            self.__client.create_group(
                GroupName=group_name,
                UserPoolId=self.__userpool_id,
                Description=description,
                Precedence=precedence,
                **param_role,
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_add_user_to_group(self, username: str, group_name: str) -> None:
        if not isinstance(username, str) or not isinstance(group_name, str):
            raise ValueError("The username and group_name should be strings.")
        try:
            self.__client.admin_add_user_to_group(
                UserPoolId=self.__userpool_id, Username=username, GroupName=group_name
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_delete_group(self, group_name: str) -> None:
        if not isinstance(group_name, str):
            raise ValueError("The group_name should be a string.")
        try:
            self.__client.delete_group(GroupName=group_name, UserPoolId=self.__userpool_id)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_remove_user_from_group(self, username: str, group_name: str) -> None:
        if not isinstance(username, str) or not isinstance(group_name, str):
            raise ValueError("The username and group_name should be strings.")
        try:
            self.__client.admin_remove_user_from_group(
                UserPoolId=self.__userpool_id, Username=username, GroupName=group_name
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def get_info_user_by_token(self, access_token: str) -> dict:
        if not isinstance(access_token, str):
            raise ValueError("The access_token should be a string.")
        try:
            data = jwt.get_unverified_claims(token=access_token)
        except JWTError:
            raise ExceptionJWTCognito("Error decoding token claims.")
        return {self.__USERNAME.lower(): data["sub"], self.__GROUPS: data.get(self.__GROUP_KEY, [])}
