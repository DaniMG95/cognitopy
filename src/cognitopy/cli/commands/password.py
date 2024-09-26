import click
from cognitopy import CognitoPy
from cognitopy.exceptions import ExceptionAuthCognito
from cognitopy.cli.commands import init_cognitopy


@click.command()
@click.option("--username", "-u", required=True, type=str)
@init_cognitopy
def forgot(cognitopy: CognitoPy, username: str):
    try:
        cognitopy.initiate_forgot_password(username=username)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("Password reset code sent successfully")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@click.option("--code", "-c", required=True, type=str)
@click.option("--new-password", "-np", required=True, type=str)
@init_cognitopy
def confirm(cognitopy: CognitoPy, username: str, code: str, new_password: str):
    try:
        cognitopy.confirm_forgot_password(username=username, confirmation_code=code, password=new_password)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("Password reset successfully")
