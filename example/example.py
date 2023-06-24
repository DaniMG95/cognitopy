from cognitopy import CognitoPy
import os
from cognitopy.enums import MessageAction, DesiredDelivery

# Instantiate CognitoPy object

COGNITO_USERPOOL_ID = "XXX-XXX-XXXXXX"
COGNITO_APP_CLIENT_ID = "XXXXXXXXXXXXXXXXXXXXXXXX"
COGNITO_APP_CLIENTE_SECRET = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Variables for using the admin functions
os.environ["AWS_ACCESS_KEY_ID"] = "XXXXXXXXXXXXXXXXXXXXXXXX"
os.environ["AWS_SECRET_ACCESS_KEY"] = "XXXXXXXXXXXXXXXXXXXXXXXX"

cognitopy = CognitoPy(
    userpool_id=COGNITO_USERPOOL_ID,
    client_id=COGNITO_APP_CLIENT_ID,
    client_secret=COGNITO_APP_CLIENTE_SECRET,
    secret_hash=True,
)

# Register a new user using context

with CognitoPy(
    userpool_id=COGNITO_USERPOOL_ID, client_id=COGNITO_APP_CLIENT_ID, client_secret=COGNITO_APP_CLIENTE_SECRET
) as cognito:
    cognito.register(username="XXXXX@mail.to", password="XXXXXXX8", user_attributes={})


# Confirm user registration

cognito.confirm_register(username="XXXXX@mail.to", confirmation_code="820850")

# Resend confirm code

cognito.resend_confirmation_code(username="XXXXX@mail.to")

# Login

tokens = cognito.login(username="XXXXX@mail.to", password="XXXXXXX")
print(tokens["access_token"], tokens["refresh_token"])

# Refresh access token

access_token = cognito.renew_access_token(access_token="XXXXXXXXX", refresh_token="XXXXXXXXX")
print(access_token)


# Check if access token is expired

is_expired = cognito.check_expired_token(access_token="XXXXXXXXX")
print(is_expired)

# Forgot password

cognito.initiate_forgot_password(username="XXXXX@mail.to")

# Confirm forgot password

cognito.confirm_forgot_password(username="XXXXX@mail.to", confirmation_code="YYYYY", password="XXXXXXX")

# Delete user

cognito.delete_user(access_token="XXXXXXXXX")

# Change password

cognito.change_password(access_token="XXXXXXXXX", previous_password="XXXXXXX", proposed_password="XXXXXXX")

# Get information about user

data_user = cognito.get_info_user_by_token(access_token="XXXXXXXXX")
print(data_user["username"], data_user["groups"])

# Admin delete user

cognito.admin_delete_user(username="XXXXX@mail.to")

# Admin create group

cognito.admin_create_group(group_name="test_group", description="test group", precedence=1)

# Admin delete group

cognito.admin_delete_group(group_name="test_group")

# Admin add user to group

cognito.admin_add_user_to_group(username="XXXXX@mail.to", group_name="test_group")

# Admin remove user from group

cognito.admin_remove_user_from_group(username="XXXXX@mail.to", group_name="test_group")

# Admin confirm user registration

cognito.admin_confirm_register(username="XXXXX@mail.to")

# Admin create user

cognito.admin_create_user(
    username="XXXXX@mail.to",
    force_alias=True,
    user_attributes={},
    message_action=MessageAction.SUPPRESS,
    desired_delivery=[DesiredDelivery.EMAIL],
)

cognito.admin_create_user(
    username="XXXXX@mail.to",
    force_alias=True,
    user_attributes={},
    message_action=MessageAction.RESEND,
    desired_delivery=[DesiredDelivery.EMAIL, DesiredDelivery.SMS],
    temporary_password="XXXXXXX",
)

# Admin disable user

cognito.admin_disable_user(username="XXXXX@mail.to")

# Admin enable user

cognito.admin_enable_user(username="XXXXX@mail.to")

# Admin get user

data_user = cognito.admin_get_user(username="XXXXX@mail.to")
print(data_user)

# Admin login

tokens = cognito.admin_login(username="XXXXX@mail.to", password="XXXXXXX")
print(tokens)

# Admin renew access token

token = cognito.admin_renew_access_token(access_token="XXXXX", refresh_token="XXXXXXX")
print(token)

# Admin list groups for user

groups = cognito.admin_list_groups_for_user(username="XXXXX@mail.to", limit=10)
print(groups)
groups = cognito.admin_list_groups_for_user(username="XXXXX@mail.to", limit=10, next_token=groups["NextToken"])
print(groups)

# Admin reset password

cognito.admin_reset_password(username="XXXXX@mail.to")

# Resolve challenge sms mfa

tokens = cognito.resolve_challenge_challenge_sms_mfa(username="XXXXX@mail.to", session="XXXXXX", sms_mfa_code="XXXXXX")
print(tokens)

# Resolve challenge new password required

tokens = cognito.resolve_challenge_new_password(username="XXXXX@mail.to", session="XXXXXX", new_password="XXXXXX")
print(tokens)
