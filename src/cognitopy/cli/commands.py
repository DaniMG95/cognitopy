import click
from cognitopy.cli.config import Config
from cognitopy import CognitoPy
from cognitopy.exceptions import ExceptionJWTCognito, ExceptionAuthCognito, ExceptionCLIValidateConfig
from functools import wraps


def init_cognitopy(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            config = Config.load_config()
        except ExceptionCLIValidateConfig as e:
            click.echo(str(e))
        else:
            with CognitoPy(userpool_id=config.userpool_id, client_id=config.app_client_id,
                           client_secret=config.app_client_secret, secret_hash=config.secret_hash) as cognitopy:
                func(cognitopy=cognitopy, *args, **kwargs)

    return wrapper


@click.command()
@click.option("--token", "-t", required=True, type=str)
@init_cognitopy
def check_expired_token(cognitopy: CognitoPy, token: str):
    try:
        result = cognitopy.check_expired_token(access_token=token)
    except ExceptionJWTCognito as e:
        click.echo(e)
    else:
        if result:
            click.echo("The token is expired")
        else:
            click.echo("The token is not expired")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@click.option("--password", "-p", required=True, type=str)
@init_cognitopy
def login(cognitopy: CognitoPy, username: str, password: str):
    try:
        tokens = cognitopy.login(username=username, password=password)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo(f'access_token = {tokens["access_token"]}\nrefresh_token = {tokens["refresh_token"]})')


@click.option("--config-file", "-f", required=False, type=str)
@click.command()
def init(config_file):
    if config_file:
        click.echo(f"Reading config from {config_file}")
        config = Config(config_file=config_file)
    else:
        data = {
            "aws": {
                "key_id": click.prompt("Please enter aws access key id", type=str),
                "access_key": click.prompt("Please enter aws secret access key", type=str),
            },
            "cognito": {
                "userpool_id": click.prompt("Please enter userpool id", type=str),
                "app_client_id": click.prompt("Please enter client id", type=str),
                "app_client_secret": click.prompt("Please enter client secret", type=str),
                "secret_hash": click.confirm("Please enter use secret hash in this session cognitopy"),
            },
        }
        config = Config(config_data=data)
    config.save_config()
    if config.status:
        click.echo("Config validated and store it in config file")
