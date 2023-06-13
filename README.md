# cognitopy
This is a package that will allow you to use the aws Cognito technology, so for now we are going to allow the management of users, authentication and creation of groups by Roles.  
The potential of this package is the ease of management of all these functionalities and only creating an object with 3 parameters.

## Installation
```bash
pip install cognitopy
```

## Variables for using the admin functions

The cognito admin functions require that we have the aws, access key and secret access key credentials defined as system environment variables.

```python
import os

os.environ["AWS_ACCESS_KEY_ID"] = 'XXXXXXXXXXXXXXXXXXXXXXXX'
os.environ["AWS_SECRET_ACCESS_KEY"] = 'XXXXXXXXXXXXXXXXXXXXXXXX'
```

## Usage
To define the cognitopy object it is necessary to give it the userpool_id, the client_id and the client_secret information.
```python
from cognitopy import CognitoPy

COGNITO_USERPOOL_ID = 'XXX-XXX-XXXXXX'
COGNITO_APP_CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXXXXXX'
COGNITO_APP_CLIENTE_SECRET = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

cognito = CognitoPy(userpool_id=COGNITO_USERPOOL_ID, client_id=COGNITO_APP_CLIENT_ID, client_secret=COGNITO_APP_CLIENTE_SECRET)
```

Now I will explain the different functions that we can use in this version, with an example.  
All these examples are in the directory example

### Register a new user
It will register a user in our cognito service and send us a confirmation message.
```python
cognitopy.register(username='XXXXX@mail.to', password='XXXXXXX8', user_attributes={})
```

### Confirm a new user
It is responsible for confirming the user from the number received by mail.
```python
cognitopy.confirm_sing_up(username='XXXXX@mail.to', confirmation_code='820850')
```

### Resend confirm code
It allows us to receive a confirmation code again, when we have previously requested to change password or register.
```python
cognitopy.resend_confirmation_code(username='XXXXX@mail.to')
```

### Login a user
It will return the access token and refresh token of a confirmed user.
```python
tokens = cognitopy.login(username='XXXXX@mail.to', password='XXXXXXX')
print(tokens['access_token'], tokens['refresh_token'])
```

### Refresh access token
It will renew the user's access token
```python
access_token = cognitopy.renew_access_token(access_token='XXXXXXXXX', refresh_token='XXXXXXXXX')
print(access_token)
```

### Check if access token is expired
Check if the access token has expired
```python
is_expired = cognitopy.check_expired_token(access_token='XXXXXXXXX')
print(is_expired)
```

### Forgot password
Allows us to change our password by sending us a confirmation code.
```python
cognitopy.initiate_forgot_password(username='XXXXX@mail.to')
```

### Confirm forgot password
Change the password of a user from the confirmation code received.
```python
cognitopy.confirm_forgot_password(username='XXXXX@mail.to', confirmation_code='YYYYY', password='XXXXXXX')
```

### Delete user
Delete the user from his access token
```python
cognitopy.delete_user(access_token='XXXXXXXXX')
```

### Change password
Change the password from your access token
```python
cognitopy.change_password(access_token='XXXXXXXXX', previous_password='XXXXXXX', proposed_password="XXXXXXX")
```

### Get user information
We obtain basic user information from the user's access token.
```python
data_user = cognitopy.get_info_user_by_token(access_token='XXXXXXXXX')
print(data_user['username'], data_user['groups'])
```

### Admin delete user
We remove a user from our service from the administrator credentials
```python
cognitopy.admin_delete_user(username='XXXXX@mail.to')
```

### Admin create group
We create a group from our service from the administrator credentials
precedence: A non-negative integer value that specifies the precedence of this group relative to the other groups that a user can belong to in the user pool. Zero is the highest precedence value. Groups with lower Precedence values take precedence over groups with higher or null Precedence values.
role_arn: The role Amazon Resource Name (ARN) for the group.
```python
cognitopy.admin_create_group(group_name='test_group', description='test group', precedence=1)
```

### Admin delete group
We remove a group from our service from the administrator credentials
```python
cognitopy.admin_delete_group(group_name='test_group')
```

### Admin add user to group
We add a user to group from our service from the administrator credentials
```python
cognitopy.admin_add_user_to_group(username='XXXXX@mail.to', group_name='test_group')
```

### Admin remove user from group
We remove a user to group from our service from the administrator credentials
```python
cognitopy.admin_remove_user_from_group(username='XXXXX@mail.to', group_name='test_group')
```


