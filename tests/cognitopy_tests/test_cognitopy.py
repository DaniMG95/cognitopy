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
from cognitopy.enums import MessageAction, DesiredDelivery
from datetime import datetime
from cognitopy.schemas import UserRegister, CodeDeliveryDetails, CodeDeliveryDetailsSchema


class TestCognito(TestCase):
    def setUp(self) -> None:
        self.cognito = CognitoPy(userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444")

    def test_dict_to_cognito(self):
        attributes = {"atb_test1": "value1", "atb_test2": "value2", "atb_test3": False}

        response = self.cognito._CognitoPy__dict_to_cognito(attributes=attributes)

        self.assertEqual(
            [
                {"Name": "atb_test1", "Value": "value1"},
                {"Name": "atb_test2", "Value": "value2"},
                {"Name": "atb_test3", "Value": "false"},
            ],
            response,
        )

    def test_dict_to_cognito_error_dict(self):
        attributes = {"atb_test1": {"test1": "value"}, "atb_test2": "value2"}

        with self.assertRaises(ValueError) as exc:
            self.cognito._CognitoPy__dict_to_cognito(attributes=attributes)

        self.assertEqual(
            "The key attributes should be a dictionary and value should be a string or number", str(exc.exception)
        )

    def test_dict_to_cognito_error_type_value_in_dict(self):
        attributes = {"atb_test1": [], "atb_test2": "value2"}

        with self.assertRaises(ValueError) as exc:
            self.cognito._CognitoPy__dict_to_cognito(attributes=attributes)

        self.assertEqual(
            "The key attributes should be a dictionary and value should be a string or number", str(exc.exception)
        )

    def test_dict_to_cognito_error_type_value(self):
        with self.assertRaises(ValueError) as exc:
            self.cognito._CognitoPy__dict_to_cognito(attributes=45)

        self.assertEqual("attributes should be a dictionary.", str(exc.exception))

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.CognitoPy._CognitoPy__get_secret_hash")
    def test_check_need_secret_hash(self, mock_get_secret_hash: Mock, mock_get_info: Mock):
        mock_get_secret_hash.side_effect = ["test-hash"]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        data = cognito._CognitoPy__check_need_secret_hash(username="test", key="SECRET_HASH")

        self.assertEqual({"SECRET_HASH": "test-hash"}, data)
        self.assertEqual([call(username="test")], mock_get_secret_hash.call_args_list)
        self.assertEqual(0, mock_get_info.call_count)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.CognitoPy._CognitoPy__get_secret_hash")
    def test_check_need_secret_hash_without_secret_hash(self, mock_get_secret_hash: Mock, mock_get_info: Mock):

        data = self.cognito._CognitoPy__check_need_secret_hash(username="test", key="test")

        self.assertEqual({}, data)
        self.assertEqual(0, mock_get_secret_hash.call_count)
        self.assertEqual(0, mock_get_info.call_count)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.CognitoPy._CognitoPy__get_secret_hash")
    def test_check_need_secret_hash_token(self, mock_get_secret_hash: Mock, mock_get_info: Mock):
        mock_get_info.side_effect = [{"username": "test1", "groups": []}]
        mock_get_secret_hash.side_effect = ["test-hash"]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        data = cognito._CognitoPy__check_need_secret_hash(access_token="token-test", key="SECRET_HASH")

        self.assertEqual({"SECRET_HASH": "test-hash"}, data)
        self.assertEqual([call(username="test1")], mock_get_secret_hash.call_args_list)
        self.assertEqual([call(access_token="token-test")], mock_get_info.call_args_list)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.CognitoPy._CognitoPy__get_secret_hash")
    def test_check_need_secret_hash_token_exception_get_info(self, mock_get_secret_hash: Mock, mock_get_info: Mock):
        mock_get_info.side_effect = [ExceptionJWTCognito("Error decoding token claims.")]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        with self.assertRaises(ExceptionJWTCognito) as exc:
            cognito._CognitoPy__check_need_secret_hash(access_token="token-test", key="test")

        self.assertEqual("Error decoding token claims.", str(exc.exception))
        self.assertEqual(0, mock_get_secret_hash.call_count)
        self.assertEqual([call(access_token="token-test")], mock_get_info.call_args_list)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.CognitoPy._CognitoPy__get_secret_hash")
    def test_check_need_secret_hash_error_type_key(self, mock_get_secret_hash: Mock, mock_get_info: Mock):
        with self.assertRaises(ValueError) as exc:
            self.cognito._CognitoPy__check_need_secret_hash(access_token="34", key=45)

        self.assertEqual("Username, access_token, key should be string", str(exc.exception))
        self.assertEqual(0, mock_get_secret_hash.call_count)
        self.assertEqual(0, mock_get_info.call_count)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.CognitoPy._CognitoPy__get_secret_hash")
    def test_check_need_secret_hash_error_type_access_token(self, mock_get_secret_hash: Mock, mock_get_info: Mock):

        with self.assertRaises(ValueError) as exc:
            self.cognito._CognitoPy__check_need_secret_hash(access_token=34, key="test")

        self.assertEqual("Username, access_token, key should be string", str(exc.exception))
        self.assertEqual(0, mock_get_secret_hash.call_count)
        self.assertEqual(0, mock_get_info.call_count)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.CognitoPy._CognitoPy__get_secret_hash")
    def test_check_need_secret_hash_error_type_username(self, mock_get_secret_hash: Mock, mock_get_info: Mock):

        with self.assertRaises(ValueError) as exc:
            self.cognito._CognitoPy__check_need_secret_hash(username=34, key="test")

        self.assertEqual("Username, access_token, key should be string", str(exc.exception))
        self.assertEqual(0, mock_get_secret_hash.call_count)
        self.assertEqual(0, mock_get_info.call_count)

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

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.renew_access_token(access_token="access_token_test", refresh_token="refresh_token_test")

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
                AuthParameters={"REFRESH_TOKEN": "refresh_token_test"},
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

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.login(username="username_test", password="password_test")

        self.assertEqual(mock_initiate_auth.call_args_list, expected_calls)
        self.assertEqual(response, expected_response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_login_error_challenge(self, mock_client: Mock):
        mock_login = mock_client.return_value.initiate_auth
        mock_login.side_effect = [{"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": "test_session"}]
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": "test1", "PASSWORD": "test1"},
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.login(username="test1", password="test1")

        self.assertEqual(mock_login.call_args_list, expected_calls)
        self.assertEqual(
            str(exc.exception),
            "The user must complete challenge auth use function "
            "admin_respond_to_auth_challenge with challenge_name="
            "NEW_PASSWORD_REQUIRED, the session is test_session.",
        )

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
                AuthParameters={"USERNAME": "username_test", "PASSWORD": "password_test"},
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
    def test_register_with_secret_hash(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up
        mock_sign_up.return_value = {
            "UserConfirmed": False,
            "UserSub": "test1232",
            "CodeDeliveryDetails": {"Destination": "d***@g***", "DeliveryMedium": "EMAIL", "AttributeName": "email"},
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                Password="password_test",
                UserAttributes=[{"Name": "email", "Value": "email_test"}],
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
                ValidationData=[{"Name": "test-v1", "Value": "value-test"}],
            )
        ]
        expected_response = UserRegister(
            UserConfirmed=False,
            UserSub="test1232",
            CodeDeliveryDetails=CodeDeliveryDetails(
                Destination="d***@g***", DeliveryMedium="EMAIL", AttributeName="email"
            ),
        )

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.register(
            username="username_test",
            password="password_test",
            user_attributes={"email": "email_test"},
            validation_data={"test-v1": "value-test"},
        )

        self.assertEqual(expected_calls, mock_sign_up.call_args_list)
        self.assertEqual(expected_response, response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_without_user_attribute(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up
        mock_sign_up.return_value = {
            "UserConfirmed": False,
            "UserSub": "test1232",
            "CodeDeliveryDetails": {"Destination": "d***@g***", "DeliveryMedium": "EMAIL", "AttributeName": "email"},
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                Password="password_test",
                UserAttributes=[],
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
                ValidationData=[{"Name": "test-v1", "Value": "value-test"}],
            )
        ]
        expected_response = UserRegister(
            UserConfirmed=False,
            UserSub="test1232",
            CodeDeliveryDetails=CodeDeliveryDetails(
                Destination="d***@g***", DeliveryMedium="EMAIL", AttributeName="email"
            ),
        )

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.register(
            username="username_test", password="password_test", validation_data={"test-v1": "value-test"}
        )

        self.assertEqual(expected_calls, mock_sign_up.call_args_list)
        self.assertEqual(expected_response, response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_without_validation(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up
        mock_sign_up.return_value = {
            "UserConfirmed": False,
            "UserSub": "test1232",
            "CodeDeliveryDetails": {"Destination": "d***@g***", "DeliveryMedium": "EMAIL", "AttributeName": "email"},
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                Password="password_test",
                UserAttributes=[{"Name": "email", "Value": "email_test"}],
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
                ValidationData=[],
            )
        ]
        expected_response = UserRegister(
            UserConfirmed=False,
            UserSub="test1232",
            CodeDeliveryDetails=CodeDeliveryDetails(
                Destination="d***@g***", DeliveryMedium="EMAIL", AttributeName="email"
            ),
        )

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.register(
            username="username_test", password="password_test", user_attributes={"email": "email_test"}
        )

        self.assertEqual(expected_calls, mock_sign_up.call_args_list)
        self.assertEqual(expected_response, response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up
        mock_sign_up.return_value = {
            "UserConfirmed": False,
            "UserSub": "test1232",
            "CodeDeliveryDetails": {"Destination": "d***@g***", "DeliveryMedium": "EMAIL", "AttributeName": "email"},
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                Password="password_test",
                UserAttributes=[{"Name": "email", "Value": "email_test"}],
                ValidationData=[{"Name": "test-v1", "Value": "value-test"}],
            )
        ]
        expected_response = UserRegister(
            UserConfirmed=False,
            UserSub="test1232",
            CodeDeliveryDetails=CodeDeliveryDetails(
                Destination="d***@g***", DeliveryMedium="EMAIL", AttributeName="email"
            ),
        )

        response = self.cognito.register(
            username="username_test",
            password="password_test",
            user_attributes={"email": "email_test"},
            validation_data={"test-v1": "value-test"},
        )

        self.assertEqual(expected_calls, mock_sign_up.call_args_list)
        self.assertEqual(expected_response, response)

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
                ValidationData=[],
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.register(
                username="username_test", password="password_test", user_attributes={"email": "email_test"}
            )

        self.assertEqual(expected_calls, mock_sign_up.call_args_list)
        self.assertEqual("An account with the given email already exists.", str(exc.exception))

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_error_type_user_attributes(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.register(
                username="username_test", password="password_test", user_attributes=["email", "email_test"]
            )

        self.assertEqual(mock_sign_up.call_count, 0)
        self.assertEqual(
            "The username and password should be strings, user_attributes and validation_data should be a " "dict.",
            str(exc.exception),
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_error_type_username(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.register(username=453, password="password_test")

        self.assertEqual(mock_sign_up.call_count, 0)
        self.assertEqual(
            "The username and password should be strings, user_attributes and validation_data should be a " "dict.",
            str(exc.exception),
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_error_type_validation_data(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.register(
                username="username_test", password="password_test", validation_data=["email", "email_test"]
            )

        self.assertEqual(mock_sign_up.call_count, 0)
        self.assertEqual(
            "The username and password should be strings, user_attributes and validation_data should be a " "dict.",
            str(exc.exception),
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_register_error_type_password(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.register(username="test_user", password=344)

        self.assertEqual(mock_sign_up.call_count, 0)
        self.assertEqual(
            "The username and password should be strings, user_attributes and validation_data should be a " "dict.",
            str(exc.exception),
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_register(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.confirm_sign_up
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                ConfirmationCode="123434",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        cognito.confirm_register(username="username_test", confirmation_code="123434")

        self.assertEqual(mock_sign_up.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_register_error(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.confirm_sign_up
        mock_sign_up.side_effect = ClientError(
            error_response={"Error": {"Message": "Username not exist."}},
            operation_name="test",
        )
        expected_calls = [call(ClientId="dtest34453", Username="username_test", ConfirmationCode="123434")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.confirm_register(username="username_test", confirmation_code="123434")

        self.assertEqual(mock_sign_up.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username not exist.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_register_error_type(self, mock_client: Mock):
        mock_sign_up = mock_client.return_value.confirm_sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.confirm_register(username=34, confirmation_code="123434")

        self.assertEqual(mock_sign_up.call_count, 0)
        self.assertEqual(str(exc.exception), "The username and confirmation_code should be strings.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resend_confirmation_code(self, mock_client: Mock):
        mock_resend_confirmation_code = mock_client.return_value.resend_confirmation_code
        mock_resend_confirmation_code.side_effect = [
            {"CodeDeliveryDetails": {"Destination": "d***@g***", "DeliveryMedium": "EMAIL", "AttributeName": "email"}}
        ]
        expected_response = CodeDeliveryDetailsSchema(
            CodeDeliveryDetails=CodeDeliveryDetails(
                Destination="d***@g***", DeliveryMedium="EMAIL", AttributeName="email"
            )
        )
        expected_calls = [call(ClientId="dtest34453", Username="username_test")]

        response = self.cognito.resend_confirmation_code(username="username_test")

        self.assertEqual(expected_calls, mock_resend_confirmation_code.call_args_list)
        self.assertEqual(expected_response, response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resend_confirmation_code_with_secret_hash(self, mock_client: Mock):
        mock_resend_confirmation_code = mock_client.return_value.resend_confirmation_code
        mock_resend_confirmation_code.side_effect = [
            {"CodeDeliveryDetails": {"Destination": "d***@g***", "DeliveryMedium": "EMAIL", "AttributeName": "email"}}
        ]
        expected_response = CodeDeliveryDetailsSchema(
            CodeDeliveryDetails=CodeDeliveryDetails(
                Destination="d***@g***", DeliveryMedium="EMAIL", AttributeName="email"
            )
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                Username="username_test",
                SecretHash="sD6vefe+JNM/kycHW3x6NhCdVMF2QbcJ2ztDjwr47DY=",
            )
        ]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.resend_confirmation_code(username="username_test")

        self.assertEqual(expected_calls, mock_resend_confirmation_code.call_args_list)
        self.assertEqual(expected_response, response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resend_confirmation_code_error(self, mock_client: Mock):
        mock_resend_confirmation_code = mock_client.return_value.resend_confirmation_code
        mock_resend_confirmation_code.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [call(ClientId="dtest34453", Username="username_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.resend_confirmation_code(username="username_test")

        self.assertEqual(expected_calls, mock_resend_confirmation_code.call_args_list)
        self.assertEqual("Username incorrect.", str(exc.exception))

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resend_confirmation_code_error_type(self, mock_client: Mock):
        mock_resend_confirmation_code = mock_client.return_value.resend_confirmation_code

        with self.assertRaises(ValueError) as exc:
            self.cognito.resend_confirmation_code(username=23)

        self.assertEqual(0, mock_resend_confirmation_code.call_count)
        self.assertEqual("The username should be a string.", str(exc.exception))

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

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        cognito.initiate_forgot_password(username="username_test")

        self.assertEqual(mock_forgot_password.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_initiate_forgot_password_error(self, mock_client: Mock):
        mock_forgot_password = mock_client.return_value.forgot_password
        mock_forgot_password.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [call(ClientId="dtest34453", Username="username_test")]

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

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        cognito.confirm_forgot_password(username="username_test", confirmation_code="12342", password="password_test")

        self.assertEqual(mock_confirm_forgot_password.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_confirm_forgot_password_error(self, mock_client: Mock):
        mock_confirm_forgot_password = mock_client.return_value.confirm_forgot_password
        mock_confirm_forgot_password.side_effect = ClientError(
            error_response={"Error": {"Message": "Username incorrect."}}, operation_name="test"
        )
        expected_calls = [
            call(ClientId="dtest34453", Username="username_test", ConfirmationCode="12342", Password="password_test")
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
            "The group_name, description and role arm should be strings and precedence should be an integer.",
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

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_confirm_register(self, mock_client: Mock):
        mock_admin_confirm_sign_up = mock_client.return_value.admin_confirm_sign_up
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]

        self.cognito.admin_confirm_register(username="test1")

        self.assertEqual(mock_admin_confirm_sign_up.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_confirm_register_error(self, mock_client: Mock):
        mock_admin_confirm_sign_up = mock_client.return_value.admin_confirm_sign_up
        mock_admin_confirm_sign_up.side_effect = ClientError(
            error_response={"Error": {"Message": "Username is incorrect."}}, operation_name="test"
        )
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_confirm_register(username="test1")

        self.assertEqual(mock_admin_confirm_sign_up.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_confirm_register_error_type(self, mock_client: Mock):
        mock_admin_confirm_sign_up = mock_client.return_value.admin_confirm_sign_up

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_confirm_register(username=3223)

        self.assertEqual(mock_admin_confirm_sign_up.call_count, 0)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_user(self, mock_client: Mock):
        mock_admin_create_user = mock_client.return_value.admin_create_user
        expected_calls = [
            call(
                UserPoolId="eu-12_test",
                Username="test1",
                UserAttributes=[{"Name": "email", "Value": "test1@mail.com"}],
                ForceAliasCreation=True,
                MessageAction="RESEND",
                DesiredDeliveryMediums=["EMAIL"],
            )
        ]

        self.cognito.admin_create_user(
            username="test1",
            user_attributes={"email": "test1@mail.com"},
            force_alias=True,
            message_action=MessageAction.RESEND,
            desired_delivery=[DesiredDelivery.EMAIL],
        )

        self.assertEqual(mock_admin_create_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_user_temporary_password(self, mock_client: Mock):
        mock_admin_create_user = mock_client.return_value.admin_create_user
        expected_calls = [
            call(
                UserPoolId="eu-12_test",
                Username="test1",
                UserAttributes=[],
                ForceAliasCreation=True,
                MessageAction="RESEND",
                DesiredDeliveryMediums=["EMAIL"],
                TemporaryPassword="test1",
            )
        ]

        self.cognito.admin_create_user(
            username="test1",
            user_attributes={},
            force_alias=True,
            message_action=MessageAction.RESEND,
            desired_delivery=[DesiredDelivery.EMAIL],
            temporary_password="test1",
        )

        self.assertEqual(mock_admin_create_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_user_error(self, mock_client: Mock):
        mock_admin_create_user = mock_client.return_value.admin_create_user
        mock_admin_create_user.side_effect = ClientError(
            error_response={"Error": {"Message": "PasswordTemporary is incorrect."}}, operation_name="test"
        )
        expected_calls = [
            call(
                UserPoolId="eu-12_test",
                Username="test1",
                UserAttributes=[],
                ForceAliasCreation=True,
                MessageAction="RESEND",
                DesiredDeliveryMediums=["EMAIL"],
                TemporaryPassword="test1",
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_create_user(
                username="test1",
                user_attributes={},
                force_alias=True,
                message_action=MessageAction.RESEND,
                desired_delivery=[DesiredDelivery.EMAIL],
                temporary_password="test1",
            )

        self.assertEqual(mock_admin_create_user.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "PasswordTemporary is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_user_error_type_message_action(self, mock_client: Mock):
        mock_admin_create_user = mock_client.return_value.admin_create_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_create_user(
                username="test1",
                user_attributes={"email": "test1@mail.com"},
                force_alias=True,
                message_action="RESEND",
                desired_delivery=[DesiredDelivery.EMAIL],
            )

        self.assertEqual(mock_admin_create_user.call_count, 0)
        self.assertEqual(str(exc.exception), "The message_action should be a MessageAction.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_user_error_type_username(self, mock_client: Mock):
        mock_admin_create_user = mock_client.return_value.admin_create_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_create_user(
                username=232,
                user_attributes={"email": "test1@mail.com"},
                force_alias=True,
                message_action=MessageAction.RESEND,
                desired_delivery=[DesiredDelivery.EMAIL],
            )

        self.assertEqual(mock_admin_create_user.call_count, 0)
        self.assertEqual(
            str(exc.exception),
            "The username should be a string, user_attributes should be a dict and " "force_alias should be a bool.",
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_user_error_type_temporary_password(self, mock_client: Mock):
        mock_admin_create_user = mock_client.return_value.admin_create_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_create_user(
                username="test1",
                user_attributes={"email": "test1@mail.com"},
                force_alias=True,
                message_action=MessageAction.RESEND,
                desired_delivery=[DesiredDelivery.EMAIL],
                temporary_password=232,
            )

        self.assertEqual(mock_admin_create_user.call_count, 0)
        self.assertEqual(str(exc.exception), "The temporary_password should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_create_user_error_type_desired_delivery(self, mock_client: Mock):
        mock_admin_create_user = mock_client.return_value.admin_create_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_create_user(
                username="test1",
                user_attributes={"email": "test1@mail.com"},
                force_alias=True,
                message_action=MessageAction.RESEND,
                desired_delivery=[DesiredDelivery.EMAIL, "SMS"],
            )

        self.assertEqual(mock_admin_create_user.call_count, 0)
        self.assertEqual(str(exc.exception), "The desired_delivery should be a List[DesiredDeliver].")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_disable_user(self, mock_client: Mock):
        mock_admin_disable_user = mock_client.return_value.admin_disable_user
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]

        self.cognito.admin_disable_user(username="test1")

        self.assertEqual(mock_admin_disable_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_disable_user_error(self, mock_client: Mock):
        mock_admin_disable_user = mock_client.return_value.admin_disable_user
        mock_admin_disable_user.side_effect = ClientError(
            error_response={"Error": {"Message": "Username is incorrect."}}, operation_name="test"
        )
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_disable_user(username="test1")

        self.assertEqual(mock_admin_disable_user.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_disable_user_error_type(self, mock_client: Mock):
        mock_admin_disable_user = mock_client.return_value.admin_disable_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_disable_user(username=23)

        self.assertEqual(mock_admin_disable_user.call_count, 0)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_enable_user(self, mock_client: Mock):
        mock_admin_enable_user = mock_client.return_value.admin_enable_user
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]

        self.cognito.admin_enable_user(username="test1")

        self.assertEqual(mock_admin_enable_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_enable_user_error(self, mock_client: Mock):
        mock_admin_enable_user = mock_client.return_value.admin_enable_user
        mock_admin_enable_user.side_effect = ClientError(
            error_response={"Error": {"Message": "Username is incorrect."}}, operation_name="test"
        )
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_enable_user(username="test1")

        self.assertEqual(mock_admin_enable_user.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_enable_user_error_type(self, mock_client: Mock):
        mock_admin_enable_user = mock_client.return_value.admin_enable_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_enable_user(username=23)

        self.assertEqual(mock_admin_enable_user.call_count, 0)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_get_user(self, mock_client: Mock):
        mock_admin_get_user = mock_client.return_value.admin_get_user
        mock_admin_get_user.return_value = {
            "Username": "test1",
            "UserAttributes": [{"Name": "email", "Value": "test@mail.com"}],
            "Enabled": True,
            "UserStatus": "CONFIRMED",
            "UserCreateDate": datetime(2022, 12, 23),
            "UserLastModifiedDate": datetime(2022, 12, 23),
        }
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]
        expected_response = {
            "username": "test1",
            "email": "test@mail.com",
            "enabled": True,
            "user_status": "CONFIRMED",
            "user_create_date": datetime(2022, 12, 23),
            "user_last_modified_date": datetime(2022, 12, 23),
        }

        response = self.cognito.admin_get_user(username="test1")

        self.assertEqual(mock_admin_get_user.call_args_list, expected_calls)
        self.assertEqual(response, expected_response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_get_user_error(self, mock_client: Mock):
        mock_admin_get_user = mock_client.return_value.admin_get_user
        mock_admin_get_user.side_effect = ClientError(
            error_response={"Error": {"Message": "Username is incorrect."}}, operation_name="test"
        )
        expected_calls = [call(UserPoolId="eu-12_test", Username="test1")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_get_user(username="test1")

        self.assertEqual(mock_admin_get_user.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_get_user_error_type(self, mock_client: Mock):
        mock_admin_get_user = mock_client.return_value.admin_get_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_get_user(username=23)

        self.assertEqual(mock_admin_get_user.call_count, 0)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_login(self, mock_client: Mock):
        mock_admin_login = mock_client.return_value.admin_initiate_auth
        mock_admin_login.return_value = {
            "AuthenticationResult": {"AccessToken": "test1232", "RefreshToken": "test2332"}
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                UserPoolId="eu-12_test",
                AuthParameters={
                    "USERNAME": "test1",
                    "PASSWORD": "test1",
                    "SECRET_HASH": "0ht/aQ+Y1wA2FL6XYkn3UoUfZu67Ik+/On25xDAlwpo=",
                },
            )
        ]
        expected_response = {"access_token": "test1232", "refresh_token": "test2332"}

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.admin_login(username="test1", password="test1")

        self.assertEqual(mock_admin_login.call_args_list, expected_calls)
        self.assertEqual(response, expected_response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_login_error(self, mock_client: Mock):
        mock_admin_login = mock_client.return_value.admin_initiate_auth
        mock_admin_login.side_effect = ClientError(
            error_response={"Error": {"Message": "Username is incorrect."}}, operation_name="test"
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                UserPoolId="eu-12_test",
                AuthParameters={"USERNAME": "test1", "PASSWORD": "test1"},
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_login(username="test1", password="test1")

        self.assertEqual(mock_admin_login.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Username is incorrect.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_login_error_challenge(self, mock_client: Mock):
        mock_admin_login = mock_client.return_value.admin_initiate_auth
        mock_admin_login.side_effect = [{"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": "test_session"}]
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                UserPoolId="eu-12_test",
                AuthParameters={"USERNAME": "test1", "PASSWORD": "test1"},
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_login(username="test1", password="test1")

        self.assertEqual(mock_admin_login.call_args_list, expected_calls)
        self.assertEqual(
            str(exc.exception),
            "The user must complete challenge auth use function "
            "admin_respond_to_auth_challenge with challenge_name="
            "NEW_PASSWORD_REQUIRED, the session is test_session.",
        )

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_login_error_type(self, mock_client: Mock):
        mock_admin_login = mock_client.return_value.admin_initiate_auth

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_login(username=34, password="test1")

        self.assertEqual(mock_admin_login.call_count, 0)
        self.assertEqual(str(exc.exception), "The username and password should be strings.")

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_renew_access_token(self, mock_client: Mock, mock_get_info: Mock):
        mock_admin_renew_access_token = mock_client.return_value.admin_initiate_auth
        mock_get_info.return_value = {"username": "test1", "groups": []}
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="REFRESH_TOKEN_AUTH",
                UserPoolId="eu-12_test",
                AuthParameters={
                    "REFRESH_TOKEN": "test2",
                    "SECRET_HASH": "0ht/aQ+Y1wA2FL6XYkn3UoUfZu67Ik+/On25xDAlwpo=",
                },
            )
        ]
        expected_calls_get_info = [call(access_token="test1")]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        cognito.admin_renew_access_token(access_token="test1", refresh_token="test2")

        self.assertEqual(mock_admin_renew_access_token.call_args_list, expected_calls)
        self.assertEqual(mock_get_info.call_args_list, expected_calls_get_info)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_renew_access_token_error_secret(self, mock_client: Mock, mock_get_info: Mock):
        mock_admin_renew_access_token = mock_client.return_value.admin_initiate_auth
        mock_get_info.return_value = {"username": 23, "groups": []}
        expected_calls_get_info = [call(access_token="test1")]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        with self.assertRaises(ValueError) as exc:
            cognito.admin_renew_access_token(access_token="test1", refresh_token="test2")

        self.assertEqual(mock_admin_renew_access_token.call_count, 0)
        self.assertEqual(mock_get_info.call_args_list, expected_calls_get_info)
        self.assertEqual(str(exc.exception), "The username should be a string.")

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_renew_access_token_error(self, mock_client: Mock, mock_get_info: Mock):
        mock_admin_renew_access_token = mock_client.return_value.admin_initiate_auth
        mock_admin_renew_access_token.side_effect = ClientError(
            error_response={"Error": {"Message": "Error connect"}}, operation_name="test"
        )
        mock_get_info.return_value = {"username": "test1", "groups": []}
        expected_calls = [
            call(
                ClientId="dtest34453",
                AuthFlow="REFRESH_TOKEN_AUTH",
                UserPoolId="eu-12_test",
                AuthParameters={"REFRESH_TOKEN": "test2"},
            )
        ]
        expected_calls_get_info = [call(access_token="test1")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_renew_access_token(access_token="test1", refresh_token="test2")

        self.assertEqual(mock_admin_renew_access_token.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Error connect")
        self.assertEqual(mock_get_info.call_args_list, expected_calls_get_info)

    @patch("cognitopy.cognitopy.CognitoPy.get_info_user_by_token")
    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_renew_access_token_error_type(self, mock_client: Mock, mock_get_info: Mock):
        mock_admin_renew_access_token = mock_client.return_value.admin_initiate_auth

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_renew_access_token(access_token=23, refresh_token="test2")

        self.assertEqual(mock_admin_renew_access_token.call_count, 0)
        self.assertEqual(str(exc.exception), "The access_token and refresh_token should be strings.")
        self.assertEqual(mock_get_info.call_count, 0)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_list_groups_for_user(self, mock_client: Mock):
        mock_admin_list_groups_for_user = mock_client.return_value.admin_list_groups_for_user
        expected_calls = [call(Username="test1", UserPoolId="eu-12_test")]

        self.cognito.admin_list_groups_for_user(username="test1")

        self.assertEqual(mock_admin_list_groups_for_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_list_groups_for_user_with_params(self, mock_client: Mock):
        mock_admin_list_groups_for_user = mock_client.return_value.admin_list_groups_for_user
        expected_calls = [call(Username="test1", UserPoolId="eu-12_test", Limit=10, NextToken="test2")]

        self.cognito.admin_list_groups_for_user(username="test1", limit=10, next_token="test2")

        self.assertEqual(mock_admin_list_groups_for_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_list_groups_for_user_token_error(self, mock_client: Mock):
        mock_admin_list_groups_for_user = mock_client.return_value.admin_list_groups_for_user
        mock_admin_list_groups_for_user.side_effect = ClientError(
            error_response={"Error": {"Message": "Error username"}}, operation_name="test"
        )
        expected_calls = [call(Username="test1", UserPoolId="eu-12_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_list_groups_for_user(username="test1")

        self.assertEqual(str(exc.exception), "Error username")
        self.assertEqual(mock_admin_list_groups_for_user.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_list_groups_for_user_token_error_type_username(self, mock_client: Mock):
        mock_admin_list_groups_for_user = mock_client.return_value.admin_list_groups_for_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_list_groups_for_user(username=342)

        self.assertEqual(str(exc.exception), "The username should be a string.")
        self.assertEqual(mock_admin_list_groups_for_user.call_count, 0)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_list_groups_for_user_token_error_type_limit(self, mock_client: Mock):
        mock_admin_list_groups_for_user = mock_client.return_value.admin_list_groups_for_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_list_groups_for_user(username="test1", limit="10", next_token="23123")

        self.assertEqual(str(exc.exception), "The limit should be an integer.")
        self.assertEqual(mock_admin_list_groups_for_user.call_count, 0)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_list_groups_for_user_token_error_type_next_token(self, mock_client: Mock):
        mock_admin_list_groups_for_user = mock_client.return_value.admin_list_groups_for_user

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_list_groups_for_user(username="test1", limit=10, next_token=23123)

        self.assertEqual(str(exc.exception), "The next_token should be a string.")
        self.assertEqual(mock_admin_list_groups_for_user.call_count, 0)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_reset_user_password(self, mock_client: Mock):
        mock_admin_reset_user_password = mock_client.return_value.admin_reset_user_password
        expected_calls = [call(Username="test1", UserPoolId="eu-12_test")]

        self.cognito.admin_reset_user_password(username="test1")

        self.assertEqual(mock_admin_reset_user_password.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_reset_user_password_error(self, mock_client: Mock):
        mock_admin_reset_user_password = mock_client.return_value.admin_reset_user_password
        mock_admin_reset_user_password.side_effect = ClientError(
            error_response={"Error": {"Message": "Error username"}}, operation_name="test"
        )
        expected_calls = [call(Username="test1", UserPoolId="eu-12_test")]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.admin_reset_user_password(username="test1")

        self.assertEqual(str(exc.exception), "Error username")
        self.assertEqual(mock_admin_reset_user_password.call_args_list, expected_calls)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_admin_reset_user_password_error_type(self, mock_client: Mock):
        mock_admin_reset_user_password = mock_client.return_value.admin_reset_user_password

        with self.assertRaises(ValueError) as exc:
            self.cognito.admin_reset_user_password(username=23)

        self.assertEqual(str(exc.exception), "The username should be a string.")
        self.assertEqual(mock_admin_reset_user_password.call_count, 0)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resolve_challenge_challenge_sms_mfa(self, mock_client: Mock):
        mock_admin_respond_to_auth_challenge = mock_client.return_value.admin_respond_to_auth_challenge
        mock_admin_respond_to_auth_challenge.return_value = {
            "AuthenticationResult": {"AccessToken": "test1232", "RefreshToken": "test2332"}
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                UserPoolId="eu-12_test",
                ChallengeName="SMS_MFA",
                Session="session_test",
                ChallengeResponses={
                    "SMS_MFA_CODE": "test_code",
                    "USERNAME": "test1",
                    "SECRET_HASH": "0ht/aQ+Y1wA2FL6XYkn3UoUfZu67Ik+/On25xDAlwpo=",
                },
            )
        ]
        expected_response = {"access_token": "test1232", "refresh_token": "test2332"}

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.resolve_challenge_challenge_sms_mfa(
            session="session_test", sms_mfa_code="test_code", username="test1"
        )

        self.assertEqual(mock_admin_respond_to_auth_challenge.call_args_list, expected_calls)
        self.assertEqual(response, expected_response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resolve_challenge_challenge_sms_mfa_error(self, mock_client: Mock):
        mock_admin_respond_to_auth_challenge = mock_client.return_value.admin_respond_to_auth_challenge
        mock_admin_respond_to_auth_challenge.side_effect = ClientError(
            error_response={"Error": {"Message": "Error username"}}, operation_name="test"
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                UserPoolId="eu-12_test",
                ChallengeName="SMS_MFA",
                Session="session_test",
                ChallengeResponses={"SMS_MFA_CODE": "test_code", "USERNAME": "test1"},
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.resolve_challenge_challenge_sms_mfa(
                session="session_test", sms_mfa_code="test_code", username="test1"
            )

        self.assertEqual(mock_admin_respond_to_auth_challenge.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Error username")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resolve_challenge_challenge_sms_mfa_error_type(self, mock_client: Mock):
        mock_admin_respond_to_auth_challenge = mock_client.return_value.admin_respond_to_auth_challenge

        with self.assertRaises(ValueError) as exc:
            self.cognito.resolve_challenge_challenge_sms_mfa(
                session="session_test", sms_mfa_code="test_code", username=334
            )

        self.assertEqual(mock_admin_respond_to_auth_challenge.call_count, 0)
        self.assertEqual(str(exc.exception), "The session. sms_mfa_code and username should be strings.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resolve_challenge_new_password(self, mock_client: Mock):
        mock_admin_respond_to_auth_challenge = mock_client.return_value.admin_respond_to_auth_challenge
        mock_admin_respond_to_auth_challenge.return_value = {
            "AuthenticationResult": {"AccessToken": "test1232", "RefreshToken": "test2332"}
        }
        expected_calls = [
            call(
                ClientId="dtest34453",
                UserPoolId="eu-12_test",
                ChallengeName="NEW_PASSWORD_REQUIRED",
                ChallengeResponses={
                    "NEW_PASSWORD": "test_password",
                    "USERNAME": "test1",
                    "SECRET_HASH": "0ht/aQ+Y1wA2FL6XYkn3UoUfZu67Ik+/On25xDAlwpo=",
                },
                Session="session_test",
            )
        ]
        expected_response = {"access_token": "test1232", "refresh_token": "test2332"}

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        response = cognito.resolve_challenge_new_password(
            session="session_test", new_password="test_password", username="test1"
        )

        self.assertEqual(mock_admin_respond_to_auth_challenge.call_args_list, expected_calls)
        self.assertEqual(response, expected_response)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resolve_challenge_new_password_error(self, mock_client: Mock):
        mock_admin_respond_to_auth_challenge = mock_client.return_value.admin_respond_to_auth_challenge
        mock_admin_respond_to_auth_challenge.side_effect = ClientError(
            error_response={"Error": {"Message": "Error username"}}, operation_name="test"
        )
        expected_calls = [
            call(
                ClientId="dtest34453",
                UserPoolId="eu-12_test",
                ChallengeName="NEW_PASSWORD_REQUIRED",
                ChallengeResponses={"NEW_PASSWORD": "test_password", "USERNAME": "test1"},
                Session="session_test",
            )
        ]

        with self.assertRaises(ExceptionAuthCognito) as exc:
            self.cognito.resolve_challenge_new_password(
                session="session_test", new_password="test_password", username="test1"
            )

        self.assertEqual(mock_admin_respond_to_auth_challenge.call_args_list, expected_calls)
        self.assertEqual(str(exc.exception), "Error username")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_resolve_challenge_new_password_error_type(self, mock_client: Mock):
        mock_admin_respond_to_auth_challenge = mock_client.return_value.admin_respond_to_auth_challenge

        with self.assertRaises(ValueError) as exc:
            self.cognito.resolve_challenge_new_password(
                session="session_test", new_password="test_password", username=334
            )

        self.assertEqual(mock_admin_respond_to_auth_challenge.call_count, 0)
        self.assertEqual(str(exc.exception), "The session, username and new_password should be strings.")

    @patch("cognitopy.cognitopy.boto3.client")
    def test_revoke_refresh_token(self, mock_client: Mock):
        mock_revoke_token = mock_client.return_value.revoke_token
        mock_revoke_token.return_value = {}
        expected_calls = [call(Token="token_test", ClientId="dtest34453", ClientSecret="dtest34334444")]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        cognito.revoke_refresh_token(token="token_test")

        self.assertEqual(expected_calls, mock_revoke_token.call_args_list)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_revoke_refresh_token_error_type(self, mock_client: Mock):
        mock_revoke_token = mock_client.return_value.revoke_token

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )
        with self.assertRaises(ValueError) as exc:
            cognito.revoke_refresh_token(token=232)

        self.assertEqual("The token should be a string.", str(exc.exception))
        self.assertEqual(0, mock_revoke_token.call_count)

    @patch("cognitopy.cognitopy.boto3.client")
    def test_revoke_refresh_token_error_client(self, mock_client: Mock):
        mock_revoke_token = mock_client.return_value.revoke_token
        mock_revoke_token.side_effect = ClientError(
            error_response={"Error": {"Message": "Error token"}}, operation_name="test"
        )
        expected_calls = [call(Token="token_test", ClientId="dtest34453", ClientSecret="dtest34334444")]

        cognito = CognitoPy(
            userpool_id="eu-12_test", client_id="dtest34453", client_secret="dtest34334444", secret_hash=True
        )

        with self.assertRaises(ExceptionAuthCognito) as exc:
            cognito.revoke_refresh_token(token="token_test")

        self.assertEqual("Error token", str(exc.exception))
        self.assertEqual(expected_calls, mock_revoke_token.call_args_list)
