from unittest import TestCase
from unittest.mock import patch, Mock, call
from freezegun import freeze_time
from jose import JWTError
from cognitopy.cognitopy import CognitoPy
from cognitopy.exceptions import (
    ExceptionJWTCognito,
    ExceptionAuthCognito,
    ExceptionConnectionCognito,
    ExceptionTokenExpired,
)
from botocore.exceptions import ClientError, EndpointConnectionError


class TestCognito(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cognito = CognitoPy(userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444")

    def test_create_cognito(self):
        cognito = CognitoPy(userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444")

        self.assertEqual(cognito.userpool_id, "eu-12_test")
        self.assertEqual(cognito.client_id, "dtest34453")
        self.assertEqual(cognito.client_secret, "dtest34334444")
        self.assertEqual(cognito.region_name, "eu-12")

    def test_create_cognito_error_type(self):

        with self.assertRaises(ValueError) as exc:
            CognitoPy(userpool_id="eu-12_test", client_id=34, client_secret="dtest34334444")

        self.assertEqual(str(exc.exception), "The userpool_id, client_id and client_secret should be strings")

    def test_create_cognito_error_userpool_id(self):

        with self.assertRaises(ValueError) as exc:
            CognitoPy(userpool_id="eu-12test", client_id="dtest34453", client_secret="dtest34334444")

        self.assertEqual(str(exc.exception), "The format userpool_id is incorrect")

    @patch("cognitopy.cognitopy.jwt.get_unverified_claims")
    @freeze_time("2023-05-19 17:45:00")
    def test_check_expired_token(self, mock_jwt: Mock):
        mock_jwt.return_value = {"exp": 1684510415, "sub": "test1"}
        expected_calls = [call(token="dummytoken")]

        check = self.cognito.check_expired_token(access_token="dummytoken")

        self.assertTrue(check)
        self.assertEqual(mock_jwt.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.jwt.get_unverified_claims")
    @freeze_time("2023-05-19 08:15:00")
    def test_check_expired_token_not_expired(self, mock_jwt: Mock):
        mock_jwt.return_value = {"exp": 1684510415, "sub": "test1"}
        expected_calls = [call(token="dummytoken")]

        check = self.cognito.check_expired_token(access_token="dummytoken")

        self.assertFalse(check)
        self.assertEqual(mock_jwt.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.jwt.get_unverified_claims")
    @freeze_time("2023-05-19 17:45:00")
    def test_check_expired_token_error_token(self, mock_jwt: Mock):
        mock_jwt.side_effect = JWTError
        expected_calls = [call(token="dummytoken")]

        with self.assertRaises(ExceptionJWTCognito) as exc:
            self.cognito.check_expired_token(access_token="dummytoken")

        self.assertEqual(str(exc.exception), "Error decoding token claims.")
        self.assertEqual(mock_jwt.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.jwt.get_unverified_claims")
    def test_check_expired_token_error_type(self, mock_jwt: Mock):

        with self.assertRaises(ValueError) as exc:
            self.cognito.check_expired_token(access_token=34)

        self.assertEqual(str(exc.exception), "The access_token should be a string.")
        self.assertEqual(mock_jwt.call_count, 0)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_renew_access_token(self, mock_client: Mock, mock_get_info: Mock):
        mock_initiate_auth = mock_client.return_value.initiate_auth
        mock_initiate_auth.return_value = {"AuthenticationResult": {"AccessToken": "test1232"}}
        mock_get_info.return_value = {"username": "test1", "groups": []}
        expected_calls_auth = [
            call(
                ClientId="dtest34453",
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={
                    "REFRESH_TOKEN": "refresh_token_test",
                    "SECRET_HASH": "0ht/aQ+Y1wA2FL6XYkn3UoUfZu67Ik+/On25xDAlwpo=",
                },
            )
        ]
        expected_calls_get_info = [call(access_token="access_token_test")]
        expected_response = "test1232"

        response = self.cognito.renew_access_token(access_token="access_token_test", refresh_token="refresh_token_test")

        self.assertEqual(mock_initiate_auth.call_args_list, expected_calls_auth)
        self.assertEqual(mock_get_info.call_args_list, expected_calls_get_info)
        self.assertEqual(response, expected_response)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_renew_access_token_error(self, mock_client: Mock, mock_get_info: Mock):
        mock_initiate_auth = mock_client.return_value.initiate_auth
        mock_initiate_auth.side_effect = ClientError(
            error_response={"Error": {"Message": "Error access token incorrect"}}, operation_name="test"
        )
        mock_get_info.return_value = {"username": "test1", "groups": []}
        expected_calls_auth = [
            call(
                ClientId="dtest34453",
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={
                    "REFRESH_TOKEN": "refresh_token_test",
                    "SECRET_HASH": "0ht/aQ+Y1wA2FL6XYkn3UoUfZu67Ik+/On25xDAlwpo=",
                },
            )
        ]
        expected_calls_get_info = [call(access_token="access_token_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.renew_access_token(access_token="access_token_test", refresh_token="refresh_token_test")

        self.assertEqual(mock_initiate_auth.call_args_list, expected_calls_auth)
        self.assertEqual(mock_get_info.call_args_list, expected_calls_get_info)
        self.assertEqual(str(exc.exception), "Error access token incorrect")

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_renew_access_token_error_type(self, mock_client: Mock, mock_get_info: Mock):
        mock_initiate_auth = mock_client.return_value.initiate_auth

        with self.assertRaises(ValueError) as exc:
            self.cognito.renew_access_token(access_token=43, refresh_token="refresh_token_test")

        self.assertEqual(mock_get_info.call_count, 0)
        self.assertEqual(mock_initiate_auth.call_count, 0)
        self.assertEqual(str(exc.exception), "The access_token and refresh_token should be strings.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_login(self, mock_client: Mock):
        mock_initiate_auth = mock_client.return_value.initiate_auth
        mock_initiate_auth.return_value = {
            "AuthenticationResult": {"AccessToken": "test1232", "RefreshToken": "test2332"}
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": "username_test",
                    "PASSWORD": "password_test",
                    "SECRET_HASH": "sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
                },
            )
        ]
        expected_response = {"access_token": "test1232", "refresh_token": "test2332"}

        response = self.cognito.login(username="username_test", password="password_test")

        self.assertEqual(mock_initiate_auth.call_args_list, expected_calls)
        self.assertEqual(response, expected_response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_login_error_client(self, mock_client: Mock):
        mock_client.side_effect = EndpointConnectionError(endpoint_url="eu-12_aws")
        expected_calls = [call("cognito-idp", region_name="eu-12")]

        with self.assertRaises(ExceptionConnectionCognito) as exc:
            self.cognito.login(username="username_test", password="password_test")

        self.assertEqual(mock_client.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), 'Could not connect to the endpoint URL: "eu-12_aws"')

    @patch("cognitopy.cognitopy.boto3.client")
    def test_login_error(self, mock_client: Mock):
        mock_initiate_auth = mock_client.return_value.initiate_auth
        mock_initiate_auth.side_effect = ClientError(
            error_response={"Error": {"Message": "Password or username incorrect"}}, operation_name="test"
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": "username_test",
                    "PASSWORD": "password_test",
                    "SECRET_HASH": "sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
                },
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.login(username="username_test", password="password_test")

        self.assertEqual(mock_initiate_auth.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Password or username incorrect")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_login_error_type(self, mock_client: Mock):
        mock_initiate_auth = mock_client.return_value.initiate_auth

        with self.assertRaises(ValueError) as exc:
            self.cognito.login(username=34, password="password_test")

        self.assertEqual(mock_initiate_auth.call_count, 0)
        self.assertEqual(str(exc.exception), "The username and password should be strings.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                Password="password_test",
                UserAttributes=[{"Name": "email", "Value": "email_test"}],
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        self.cognito.register(
            username="username_test", password="password_test", user_attributes={"email": "email_test"}
        )

        self.assertEqual(mock_sign_up.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_error(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up
        mock_sign_up.side_effect = ClientError(
            error_response={"Error": {"Message": "An account with the given email already exists."}},
            operation_name="test",
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                Password="password_test",
                UserAttributes=[{"Name": "email", "Value": "email_test"}],
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.register(
                username="username_test", password="password_test", user_attributes={"email": "email_test"}
            )

        self.assertEqual(mock_sign_up.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "An account with the given email already exists.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_error_type(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.register(
                username="username_test", password="password_test", user_attributes=["email", "email_test"]
            )

        self.assertEqual(mock_sign_up.call_count, 0)
        self.assertEqual(
            str(exc.exception), "The username, password should be strings and" " user_attributes should be a dict."
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_sing_up(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.confirm_sign_up
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                ConfirmationCode="123434",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        self.cognito.confirm_sing_up(username="username_test", confirmation_code="123434")

        self.assertEqual(mock_sign_up.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_sing_up_error(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.confirm_sign_up
        mock_sign_up.side_effect = ClientError(
            error_response={"Error": {"Message": "Username not exist."}},
            operation_name="test",
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                ConfirmationCode="123434",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.confirm_sing_up(username="username_test", confirmation_code="123434")

        self.assertEqual(mock_sign_up.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username not exist.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_sing_up_error_type(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.confirm_sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.confirm_sing_up(username=34, confirmation_code="123434")

        self.assertEqual(mock_sign_up.call_count, 0)
        self.assertEqual(str(exc.exception), "The username and confirmation_code should be strings.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resend_confirmation_code(self, mock_client: Mock):
        mock_resend_confirmation_code = mock_client.return_value.resend_confirmation_code
        expected_calls = [call(ClientId="dtest34453", Username="username_test")]

        self.cognito.resend_confirmation_code(username="username_test")

        self.assertEqual(mock_resend_confirmation_code.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resend_confirmation_code_error(self, mock_client: Mock):
        mock_resend_confirmation_code = mock_client.return_value.resend_confirmation_code
        mock_resend_confirmation_code.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [call(ClientId="dtest34453", Username="username_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.resend_confirmation_code(username="username_test")

        self.assertEqual(mock_resend_confirmation_code.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resend_confirmation_code_error_type(self, mock_client: Mock):
        mock_resend_confirmation_code = mock_client.return_value.resend_confirmation_code

        with self.assertRaises(ValueError) as exc:
            self.cognito.resend_confirmation_code(username=23)

        self.assertEqual(mock_resend_confirmation_code.call_count, 0)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_initiate_forgot_password(self, mock_client: Mock):
        mock_forgot_password = mock_client.return_value.forgot_password
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        self.cognito.initiate_forgot_password(username="username_test")

        self.assertEqual(mock_forgot_password.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_initiate_forgot_password_error(self, mock_client: Mock):
        mock_forgot_password = mock_client.return_value.forgot_password
        mock_forgot_password.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.initiate_forgot_password(username="username_test")

        self.assertEqual(mock_forgot_password.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_initiate_forgot_password_error_type(self, mock_client: Mock):
        mock_forgot_password = mock_client.return_value.forgot_password

        with self.assertRaises(ValueError) as exc:
            self.cognito.initiate_forgot_password(username=23)

        self.assertEqual(mock_forgot_password.call_count, 0)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_delete_user(self, mock_client: Mock, mock_expired_token: Mock):
        mock_delete_user = mock_client.return_value.delete_user
        mock_expired_token.return_value = False
        expected_calls_delete = [call(AccessToken="access_token_test")]
        expected_calls_expired = [call(access_token="access_token_test")]

        self.cognito.delete_user(access_token="access_token_test")

        self.assertEqual(mock_delete_user.call_args_list, expected_calls_delete)
        self.assertEqual(mock_expired_token.call_args_list, expected_calls_expired)

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_delete_user_error_expired_token(self, mock_client: Mock, mock_expired_token: Mock):
        mock_delete_user = mock_client.return_value.delete_user
        mock_expired_token.return_value = True
        expected_calls_expired = [call(access_token="access_token_test")]

        with self.assertRaises(ExceptionTokenExpired) as exc:
            self.cognito.delete_user(access_token="access_token_test")

        self.assertEqual(mock_delete_user.call_count, 0)
        self.assertEqual(mock_expired_token.call_args_list, expected_calls_expired)
        self.assertEqual(str(exc.exception), "Token expired")

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_delete_user_error(self, mock_client: Mock, mock_expired_token: Mock):
        mock_delete_user = mock_client.return_value.delete_user
        mock_delete_user.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        mock_expired_token.return_value = False
        expected_calls_delete = [call(AccessToken="access_token_test")]
        expected_calls_expired = [call(access_token="access_token_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.delete_user(access_token="access_token_test")

        self.assertEqual(mock_delete_user.call_args_list, expected_calls_delete)
        self.assertEqual(mock_expired_token.call_args_list, expected_calls_expired)
        self.assertEqual(str(exc.exception), "Username incorrect.")

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_delete_user_error_type(self, mock_client: Mock, mock_expired_token: Mock):
        mock_delete_user = mock_client.return_value.delete_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.delete_user(access_token=234)

        self.assertEqual(mock_delete_user.call_count, 0)
        self.assertEqual(mock_expired_token.call_count, 0)
        self.assertEqual(str(exc.exception), "The access_token should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_forgot_password(self, mock_client: Mock):
        mock_confirm_forgot_password = mock_client.return_value.confirm_forgot_password
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                ConfirmationCode="12342",
                Password="password_test",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        self.cognito.confirm_forgot_password(
            username="username_test", confirmation_code="12342", password="password_test"
        )

        self.assertEqual(mock_confirm_forgot_password.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_forgot_password_error(self, mock_client: Mock):
        mock_confirm_forgot_password = mock_client.return_value.confirm_forgot_password
        mock_confirm_forgot_password.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                ConfirmationCode="12342",
                Password="password_test",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.confirm_forgot_password(
                username="username_test", confirmation_code="12342", password="password_test"
            )

        self.assertEqual(mock_confirm_forgot_password.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_forgot_password_error_type(self, mock_client: Mock):
        mock_confirm_forgot_password = mock_client.return_value.confirm_forgot_password

        with self.assertRaises(ValueError) as exc:
            self.cognito.confirm_forgot_password(
                username="username_test", confirmation_code=23344, password="password_test"
            )

        self.assertEqual(mock_confirm_forgot_password.call_count, 0)
        self.assertEqual(str(exc.exception), "The username, confirmation_code and password should be strings.")

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_change_password(self, mock_client: Mock, mock_expired_token: Mock):
        mock_change_password = mock_client.return_value.change_password
        mock_expired_token.return_value = False
        expected_calls = [
            call(AccessToken="access_token_test", PreviousPassword="password1", ProposedPassword="password2")
        ]
        expected_calls_expired = [call(access_token="access_token_test")]

        self.cognito.change_password(
            access_token="access_token_test", previous_password="password1", proposed_password="password2"
        )

        self.assertEqual(mock_change_password.call_args_list, expected_calls)
        self.assertEqual(mock_expired_token.call_args_list, expected_calls_expired)

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_change_password_error_expired_token(self, mock_client: Mock, mock_expired_token: Mock):
        mock_change_password = mock_client.return_value.change_password
        mock_expired_token.return_value = True
        expected_calls = [call(access_token="access_token_test")]

        with self.assertRaises(ExceptionTokenExpired) as exc:
            self.cognito.change_password(
                access_token="access_token_test", previous_password="password1", proposed_password="password2"
            )

        self.assertEqual(mock_change_password.call_count, 0)
        self.assertEqual(mock_expired_token.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Token expired")

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_change_password_error(self, mock_client: Mock, mock_expired_token: Mock):
        mock_change_password = mock_client.return_value.change_password
        mock_change_password.side_effect = ClientError(
            error_response={"Error": {"Message": "Password incorrect."}}, operation_name="test"
        )
        mock_expired_token.return_value = False
        expected_calls_change = [
            call(AccessToken="access_token_test", PreviousPassword="password1", ProposedPassword="password2")
        ]
        expected_calls_expired = [call(access_token="access_token_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.change_password(
                access_token="access_token_test", previous_password="password1", proposed_password="password2"
            )

        self.assertEqual(mock_change_password.call_args_list, expected_calls_change)
        self.assertEqual(mock_expired_token.call_args_list, expected_calls_expired)
        self.assertEqual(str(exc.exception), "Password incorrect.")

    @patch("cognitopy.cognitopy.CognitoPy.check_expired_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_change_password_error_type(self, mock_client: Mock, mock_expired_token: Mock):
        mock_change_password = mock_client.return_value.change_password

        with self.assertRaises(ValueError) as exc:
            self.cognito.change_password(
                access_token="access_token_test", previous_password=23, proposed_password="password2"
            )

        self.assertEqual(mock_change_password.call_count, 0)
        self.assertEqual(mock_expired_token.call_count, 0)
        self.assertEqual(
            str(exc.exception), "The previous_password, proposed_password and access_token " "should be strings."
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_delete_user(self, mock_client: Mock):
        mock_admin_delete_user = mock_client.return_value.admin_delete_user
        expected_calls = [call(UserPoolId="eu-12_test", Username="username_test")]

        self.cognito.admin_delete_user(username="username_test")

        self.assertEqual(mock_admin_delete_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_delete_user_error(self, mock_client: Mock):
        mock_admin_delete_user = mock_client.return_value.admin_delete_user
        mock_admin_delete_user.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [call(UserPoolId="eu-12_test", Username="username_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_delete_user(username="username_test")

        self.assertEqual(mock_admin_delete_user.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_delete_user_error_type(self, mock_client: Mock):
        mock_admin_delete_user = mock_client.return_value.admin_delete_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_delete_user(username=34)

        self.assertEqual(mock_admin_delete_user.call_count, 0)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_group(self, mock_client: Mock):
        mock_create_group = mock_client.return_value.create_group
        expected_calls = [
            call(GroupName="test1", Description="test1", Precedence=1, RoleArn="arn_test", UserPoolId="eu-12_test")
        ]

        self.cognito.admin_create_group(group_name="test1", description="test1", precedence=1, role_arn="arn_test")

        self.assertEqual(mock_create_group.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_group_without_role(self, mock_client: Mock):
        mock_create_group = mock_client.return_value.create_group
        expected_calls = [call(GroupName="test1", Description="test1", Precedence=1, UserPoolId="eu-12_test")]

        self.cognito.admin_create_group(group_name="test1", description="test1", precedence=1)

        self.assertEqual(mock_create_group.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_group_error(self, mock_client: Mock):
        mock_create_group = mock_client.return_value.create_group
        mock_create_group.side_effect = ClientError(
            error_response={"Error": {"Message": "Precedence incorrect."}}, operation_name="test"
        )
        expected_calls = [call(GroupName="test1", Description="test1", Precedence=1, UserPoolId="eu-12_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_create_group(group_name="test1", description="test1", precedence=1)

        self.assertEqual(mock_create_group.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Precedence incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_group_error_type(self, mock_client: Mock):
        mock_create_group = mock_client.return_value.create_group

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_create_group(group_name="test1", description="test1", precedence="1")

        self.assertEqual(mock_create_group.call_count, 0)
        self.assertEqual(
            str(exc.exception),
            "The group_name, description and role arm should be strings" " and precedence should be an integer.",
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_add_user_to_group(self, mock_client: Mock):
        mock_add_user_to_group = mock_client.return_value.admin_add_user_to_group
        expected_calls = [call(Username="test1", GroupName="test_group", UserPoolId="eu-12_test")]

        self.cognito.admin_add_user_to_group(group_name="test_group", username="test1")

        self.assertEqual(mock_add_user_to_group.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_add_user_to_group_error(self, mock_client: Mock):
        mock_add_user_to_group = mock_client.return_value.admin_add_user_to_group
        mock_add_user_to_group.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [call(Username="test1", GroupName="test_group", UserPoolId="eu-12_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_add_user_to_group(group_name="test_group", username="test1")

        self.assertEqual(mock_add_user_to_group.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_add_user_to_group_error_type(self, mock_client: Mock):
        mock_add_user_to_group = mock_client.return_value.admin_add_user_to_group

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_add_user_to_group(group_name="test_group", username=1)

        self.assertEqual(mock_add_user_to_group.call_count, 0)
        self.assertEqual(str(exc.exception), "The username and group_name should be strings.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_delete_group(self, mock_client: Mock):
        mock_delete_group = mock_client.return_value.delete_group
        expected_calls = [call(GroupName="test_group", UserPoolId="eu-12_test")]

        self.cognito.admin_delete_group(group_name="test_group")

        self.assertEqual(mock_delete_group.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_delete_group_error(self, mock_client: Mock):
        mock_delete_group = mock_client.return_value.delete_group
        mock_delete_group.side_effect = ClientError(
            error_response={"Error": {"Message": "Group name is incorrect."}}, operation_name="test"
        )
        expected_calls = [call(GroupName="test_group", UserPoolId="eu-12_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_delete_group(group_name="test_group")

        self.assertEqual(mock_delete_group.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Group name is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_delete_group_error_type(self, mock_client: Mock):
        mock_delete_group = mock_client.return_value.delete_group

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_delete_group(group_name=1)

        self.assertEqual(mock_delete_group.call_count, 0)
        self.assertEqual(str(exc.exception), "The group_name should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_remove_user_from_group(self, mock_client: Mock):
        mock_remove_user_from_group = mock_client.return_value.admin_remove_user_from_group
        expected_calls = [call(GroupName="test_group", Username="test1", UserPoolId="eu-12_test")]

        self.cognito.admin_remove_user_from_group(group_name="test_group", username="test1")

        self.assertEqual(mock_remove_user_from_group.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_remove_user_from_group_error(self, mock_client: Mock):
        mock_remove_user_from_group = mock_client.return_value.admin_remove_user_from_group
        mock_remove_user_from_group.side_effect = ClientError(
            error_response={"Error": {"Message": "Group name is incorrect."}}, operation_name="test"
        )
        expected_calls = [call(GroupName="test_group", Username="test1", UserPoolId="eu-12_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_remove_user_from_group(group_name="test_group", username="test1")

        self.assertEqual(mock_remove_user_from_group.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Group name is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_remove_user_from_group_error_type(self, mock_client: Mock):
        mock_remove_user_from_group = mock_client.return_value.admin_remove_user_from_group

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_remove_user_from_group(group_name="test_group", username=1)

        self.assertEqual(mock_remove_user_from_group.call_count, 0)
        self.assertEqual(str(exc.exception), "The username and group_name should be strings.")

    @patch("cognitopy.cognitopy.jwt.get_unverified_claims")
    def test_get_user(self, mock_jwt: Mock):
        mock_jwt.return_value = {"sub": "test1", "cognito:groups": ["test_group"]}
        expected_calls = [call(token="test_token")]

        result = self.cognito.get_info_user_by_token(access_token="test_token")

        self.assertEqual(mock_jwt.call_args_list, expected_calls)
        self.assertEqual(result, {"username": "test1", "groups": ["test_group"]})

    @patch("cognitopy.cognitopy.jwt.get_unverified_claims")
    def test_get_user_error(self, mock_jwt: Mock):
        mock_jwt.side_effect = JWTError
        expected_calls = [call(token="test_token")]

        with self.assertRaises(ExceptionJWTCognito) as exc:
            self.cognito.get_info_user_by_token(access_token="test_token")

        self.assertEqual(mock_jwt.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Error decoding token claims.")

    @patch("cognitopy.cognitopy.jwt.get_unverified_claims")
    def test_get_user_error_type(self, mock_jwt: Mock):
        mock_jwt.return_value = {"sub": "test1", "cognito:groups": ["test_group"]}

        with self.assertRaises(ValueError) as exc:
            self.cognito.get_info_user_by_token(access_token=3)

        self.assertEqual(mock_jwt.call_count, 0)
        self.assertEqual(str(exc.exception), "The access_token should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    @patch("cognitopy.cognitopy.CognitoPy.admin_delete_user")
    def test_context_manager(self, mock_create_user: Mock, mock_client: Mock):
        mock_close = mock_client.return_value.close

        with CognitoPy(userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444") as cognito:
            cognito.admin_delete_user(username="test1")

        self.assertEqual(mock_create_user.call_args_list, [call(username="test1")])
        self.assertEqual(mock_close.call_count, 1)
