import click
from cognitopy import CognitoPy
from cognitopy.exceptions import ExceptionJWTCognito
from cognitopy.cli.commands import init_cognitopy


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
