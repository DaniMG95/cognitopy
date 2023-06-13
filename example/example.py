from cognitopy import CognitoPy
import os

# Instantiate CognitoPy object

COGNITO_USERPOOL_ID = "XXX-XXX-XXXXXX"
COGNITO_APP_CLIENT_ID = "XXXXXXXXXXXXXXXXXXXXXXXX"
COGNITO_APP_CLIENTE_SECRET = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Variables for using the admin functions
os.environ["AWS_ACCESS_KEY_ID"] = "XXXXXXXXXXXXXXXXXXXXXXXX"
os.environ["AWS_SECRET_ACCESS_KEY"] = "XXXXXXXXXXXXXXXXXXXXXXXX"


cognitopy = CognitoPy(
    userpool_id=COGNITO_USERPOOL_ID, client_id=COGNITO_APP_CLIENT_ID, client_secret=COGNITO_APP_CLIENTE_SECRET
)

# Register a new user

cognitopy.register(username="XXXXX@mail.to", password="XXXXXXX8", user_attributes={})

# Confirm user registration

cognitopy.confirm_sing_up(username="XXXXX@mail.to", confirmation_code="820850")

# Resend confirm code

cognitopy.resend_confirmation_code(username="XXXXX@mail.to")

# Login

tokens = cognitopy.login(username="XXXXX@mail.to", password="XXXXXXX")
print(tokens["access_token"], tokens["refresh_token"])

# Refresh access token

access_token = cognitopy.renew_access_token(access_token="XXXXXXXXX", refresh_token="XXXXXXXXX")
print(access_token)


# Check if access token is expired

is_expired = cognitopy.check_expired_token(access_token="XXXXXXXXX")
print(is_expired)

# Forgot password

cognitopy.initiate_forgot_password(username="XXXXX@mail.to")

# Confirm forgot password

cognitopy.confirm_forgot_password(username="XXXXX@mail.to", confirmation_code="YYYYY", password="XXXXXXX")

# Delete user

cognitopy.delete_user(access_token="XXXXXXXXX")

# Change password

cognitopy.change_password(access_token="XXXXXXXXX", previous_password="XXXXXXX", proposed_password="XXXXXXX")

# Get information about user

data_user = cognitopy.get_info_user_by_token(access_token="XXXXXXXXX")
print(data_user["username"], data_user["groups"])

# Admin delete user

cognitopy.admin_delete_user(username="XXXXX@mail.to")

# Admin create group

cognitopy.admin_create_group(group_name="test_group", description="test group", precedence=1)

# Admin delete group

cognitopy.admin_delete_group(group_name="test_group")

# Admin add user to group

cognitopy.admin_add_user_to_group(username="XXXXX@mail.to", group_name="test_group")

# Admin remove user from group

cognitopy.admin_remove_user_from_group(username="XXXXX@mail.to", group_name="test_group")
