from botocore.exceptions import ClientError, EndpointConnectionError
import boto3
import hmac
import hashlib
import base64
from datetime import datetime
from jose import jwt, JWTError
from .exceptions import ExceptionJWTCognito, ExceptionAuthCognito, ExceptionConnectionCognito, ExceptionTokenExpired
from .enums import MessageAction, DesiredDelivery, AuthFlow, AdminAuthFlow, ChallengeName


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
    __SMS_MFA_CODE = "SMS_MFA_CODE"
    __CHALLENGE_NAME = "ChallengeName"
    __SECRET_HASH_ARG = "SecretHash"

    def __init__(self, userpool_id: str, client_id: str, client_secret: str, secret_hash: bool = False):
        if not isinstance(userpool_id, str) or not isinstance(client_id, str) or not isinstance(client_secret, str):
            raise ValueError("The userpool_id, client_id and client_secret should be strings")
        if "_" in userpool_id:
            self.__region_name = userpool_id.split("_")[0]
        else:
            raise ValueError("The format userpool_id is incorrect")
        self.__userpool_id = userpool_id
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__secret_hash = secret_hash

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close_connection()

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
        return [
            {"Name": key, "Value": str(value).lower() if isinstance(value, bool) else value}
            for key, value in attributes.items()
        ]

    def __user_to_dict(self, user: dict) -> dict:
        data = {
            self.__USERNAME.lower(): user[self.__USERNAME.capitalize()],
            "enabled": user["Enabled"],
            "user_status": user["UserStatus"],
            "user_create_date": user["UserCreateDate"],
            "user_last_modified_date": user["UserLastModifiedDate"],
        }
        for attribute in user["UserAttributes"]:
            data[attribute["Name"]] = attribute["Value"]
        return data

    def __check_need_secret_hash(
        self, data: dict, key_secret_hash: str, username: str = None, access_token: str = None
    ) -> None:
        if not username:
            username = self.get_info_user_by_token(access_token=access_token)[self.__USERNAME.lower()]
        if self.__secret_hash:
            data[key_secret_hash] = self.__get_secret_hash(username=username)

    def __initiate_auth(self, auth_parameters: dict, auth_flow: AdminAuthFlow | AuthFlow, admin: bool = False) -> dict:
        try:
            args = {}
            if admin:
                args["UserPoolId"] = self.__userpool_id
                function_auth = self.__client.admin_initiate_auth
            else:
                function_auth = self.__client.initiate_auth
            response = function_auth(
                ClientId=self.__client_id, AuthFlow=auth_flow.value, AuthParameters=auth_parameters, **args
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])
        return response

    def __admin_respond_to_auth_challenge(self, challenge_name: ChallengeName, session: str, challenge_responses: dict):
        self.__check_need_secret_hash(
            username=challenge_responses[self.__USERNAME], data=challenge_responses, key_secret_hash=self.__SECRET_HASH
        )
        try:
            response = self.__client.admin_respond_to_auth_challenge(
                UserPoolId=self.__userpool_id,
                ClientId=self.__client_id,
                ChallengeName=challenge_name.value,
                ChallengeResponses=challenge_responses,
                Session=session,
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])
        return response

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

    def close_connection(self) -> None:
        self.__client.close()

    def renew_access_token(self, access_token: str, refresh_token: str) -> str:
        if not isinstance(access_token, str) or not isinstance(refresh_token, str):
            raise ValueError("The access_token and refresh_token should be strings.")
        auth_parameters = {
            self.__REFRESH_TOKEN_KEY.upper(): refresh_token,
        }
        self.__check_need_secret_hash(
            access_token=access_token, data=auth_parameters, key_secret_hash=self.__SECRET_HASH
        )

        response = self.__initiate_auth(auth_parameters=auth_parameters, auth_flow=AuthFlow.REFRESH_TOKEN_AUTH)
        return response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN]

    def login(self, username: str, password: str) -> dict:
        if not isinstance(username, str) or not isinstance(password, str):
            raise ValueError("The username and password should be strings.")
        auth_parameters = {self.__USERNAME: username, self.__PASSWORD: password}
        self.__check_need_secret_hash(username=username, data=auth_parameters, key_secret_hash=self.__SECRET_HASH)
        response = self.__initiate_auth(auth_flow=AuthFlow.USER_PASSWORD_AUTH, auth_parameters=auth_parameters)
        if self.__CHALLENGE_NAME in response:
            raise ExceptionAuthCognito(
                f"The user must complete challenge auth use function "
                f"admin_respond_to_auth_challenge with challenge_name="
                f"{response['ChallengeName']}, the session is {response['Session']}."
            )
        return {
            self.__ACCESS_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN],
            self.__REFRESH_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__REFRESH_TOKEN],
        }

    def register(self, username: str, user_attributes: dict, password: str) -> str:
        if not isinstance(username, str) or not isinstance(user_attributes, dict) or not isinstance(password, str):
            raise ValueError("The username, password should be strings and user_attributes should be a dict.")
        cognito_attributes = self.__dict_to_cognito(user_attributes)
        arg_secret_hash = {}
        self.__check_need_secret_hash(username=username, data=arg_secret_hash, key_secret_hash=self.__SECRET_HASH_ARG)
        try:
            response = self.__client.sign_up(
                ClientId=self.__client_id,
                Username=username,
                Password=password,
                UserAttributes=cognito_attributes,
                **arg_secret_hash,
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])
        return response["UserSub"]

    def resend_confirmation_code(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        arg_secret_hash = {}
        self.__check_need_secret_hash(username=username, data=arg_secret_hash, key_secret_hash=self.__SECRET_HASH_ARG)
        try:
            self.__client.resend_confirmation_code(ClientId=self.__client_id, Username=username, **arg_secret_hash)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def confirm_register(self, username: str, confirmation_code: str) -> None:
        if not isinstance(username, str) or not isinstance(confirmation_code, str):
            raise ValueError("The username and confirmation_code should be strings.")
        arg_secret_hash = {}
        self.__check_need_secret_hash(username=username, data=arg_secret_hash, key_secret_hash=self.__SECRET_HASH_ARG)
        try:
            self.__client.confirm_sign_up(
                ClientId=self.__client_id, Username=username, ConfirmationCode=confirmation_code, **arg_secret_hash
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def initiate_forgot_password(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        arg_secret_hash = {}
        self.__check_need_secret_hash(username=username, data=arg_secret_hash, key_secret_hash=self.__SECRET_HASH_ARG)
        try:
            self.__client.forgot_password(ClientId=self.__client_id, Username=username, **arg_secret_hash)
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
        arg_secret_hash = {}
        self.__check_need_secret_hash(username=username, data=arg_secret_hash, key_secret_hash=self.__SECRET_HASH_ARG)
        try:
            self.__client.confirm_forgot_password(
                ClientId=self.__client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=password,
                **arg_secret_hash,
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

    def admin_confirm_register(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            self.__client.admin_confirm_sign_up(UserPoolId=self.__userpool_id, Username=username)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_create_user(
        self,
        username: str,
        user_attributes: dict,
        force_alias: bool,
        message_action: MessageAction,
        desired_delivery: list[DesiredDelivery],
        temporary_password: str = None,
    ) -> None:
        if not isinstance(username, str) or not isinstance(user_attributes, dict) or not isinstance(force_alias, bool):
            raise ValueError(
                "The username should be a string, user_attributes should be a dict and force_alias should be a bool."
            )
        if temporary_password and not isinstance(temporary_password, str):
            raise ValueError("The temporary_password should be a string.")
        if not isinstance(message_action, MessageAction):
            raise ValueError("The message_action should be a MessageAction.")
        if not isinstance(desired_delivery, list) or not all(
            isinstance(item, DesiredDelivery) for item in desired_delivery
        ):
            raise ValueError("The desired_delivery should be a List[DesiredDeliver].")
        cognito_attributes = self.__dict_to_cognito(user_attributes)
        arg_password = {}
        if temporary_password:
            arg_password = {"TemporaryPassword": temporary_password}
        try:
            self.__client.admin_create_user(
                UserPoolId=self.__userpool_id,
                Username=username,
                UserAttributes=cognito_attributes,
                ForceAliasCreation=force_alias,
                MessageAction=message_action.value,
                DesiredDeliveryMediums=[item.value for item in desired_delivery],
                **arg_password,
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_disable_user(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            self.__client.admin_disable_user(UserPoolId=self.__userpool_id, Username=username)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_enable_user(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            self.__client.admin_enable_user(UserPoolId=self.__userpool_id, Username=username)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def admin_get_user(self, username: str) -> dict:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            response = self.__client.admin_get_user(UserPoolId=self.__userpool_id, Username=username)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])
        return self.__user_to_dict(user=response)

    def admin_login(self, username: str, password: str) -> dict:
        if not isinstance(username, str) or not isinstance(password, str):
            raise ValueError("The username and password should be strings.")
        auth_parameters = {
            self.__USERNAME: username,
            self.__PASSWORD: password,
        }
        self.__check_need_secret_hash(username=username, data=auth_parameters, key_secret_hash=self.__SECRET_HASH)
        response = self.__initiate_auth(
            auth_flow=AdminAuthFlow.ADMIN_USER_PASSWORD_AUTH, auth_parameters=auth_parameters, admin=True
        )
        if self.__CHALLENGE_NAME in response:
            raise ExceptionAuthCognito(
                f"The user must complete challenge auth use function "
                f"admin_respond_to_auth_challenge with challenge_name="
                f"{response['ChallengeName']}, the session is {response['Session']}."
            )
        return {
            self.__ACCESS_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN],
            self.__REFRESH_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__REFRESH_TOKEN],
        }

    def admin_renew_access_token(self, access_token: str, refresh_token: str) -> str:
        if not isinstance(access_token, str) or not isinstance(refresh_token, str):
            raise ValueError("The access_token and refresh_token should be strings.")
        auth_parameters = {
            self.__REFRESH_TOKEN_KEY.upper(): refresh_token,
        }
        self.__check_need_secret_hash(
            access_token=access_token, data=auth_parameters, key_secret_hash=self.__SECRET_HASH
        )
        response = self.__initiate_auth(
            auth_flow=AdminAuthFlow.REFRESH_TOKEN_AUTH, auth_parameters=auth_parameters, admin=True
        )
        return response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN]

    def admin_list_groups_for_user(self, username: str, limit: int = None, next_token: str = None) -> dict:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        if limit and not isinstance(limit, int):
            raise ValueError("The limit should be an integer.")
        if next_token and not isinstance(next_token, str):
            raise ValueError("The next_token should be a string.")
        optionals_args = {}
        if limit:
            optionals_args["Limit"] = limit
        if next_token:
            optionals_args["NextToken"] = next_token
        try:
            response = self.__client.admin_list_groups_for_user(
                Username=username, UserPoolId=self.__userpool_id, **optionals_args
            )
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])
        return response

    def admin_reset_user_password(self, username: str) -> None:
        if not isinstance(username, str):
            raise ValueError("The username should be a string.")
        try:
            self.__client.admin_reset_user_password(UserPoolId=self.__userpool_id, Username=username)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])

    def resolve_challenge_challenge_sms_mfa(self, session: str, sms_mfa_code: str, username: str) -> dict:
        if not isinstance(session, str) or not isinstance(sms_mfa_code, str) or not isinstance(username, str):
            raise ValueError("The session. sms_mfa_code and username should be strings.")
        challenge_responses = {self.__USERNAME: username, self.__SMS_MFA_CODE: sms_mfa_code}
        response = self.__admin_respond_to_auth_challenge(
            session=session, challenge_responses=challenge_responses, challenge_name=ChallengeName.SMS_MFA
        )
        return {
            self.__ACCESS_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN],
            self.__REFRESH_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__REFRESH_TOKEN],
        }

    def resolve_challenge_new_password(self, session: str, username: str, new_password: str) -> dict:
        if not isinstance(session, str) or not isinstance(username, str) or not isinstance(new_password, str):
            raise ValueError("The session, username and new_password should be strings.")

        challenge_responses = {self.__USERNAME: username, "NEW_PASSWORD": new_password}
        response = self.__admin_respond_to_auth_challenge(
            session=session, challenge_responses=challenge_responses, challenge_name=ChallengeName.NEW_PASSWORD_REQUIRED
        )
        return {
            self.__ACCESS_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__ACCESS_TOKEN],
            self.__REFRESH_TOKEN_KEY: response[self.__AUTHENTICATION_RESULT][self.__REFRESH_TOKEN],
        }

    def revoke_refresh_token(self, token: str) -> None:
        if not isinstance(token, str):
            raise ValueError("The token should be a string.")
        try:
            self.__client.revoke_token(Token=token, ClientId=self.__client_id, ClientSecret=self.__client_secret)
        except ClientError as e:
            raise ExceptionAuthCognito(e.response[self.__ERROR][self.__MESSAGE])
