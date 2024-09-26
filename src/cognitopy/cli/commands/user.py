import click
from cognitopy import CognitoPy
from cognitopy.exceptions import ExceptionAuthCognito
from cognitopy.cli.commands import init_cognitopy


@click.command()
@click.option("--username", "-u", required=True, type=str)
@click.option("--password", "-p", required=True, type=str)
@init_cognitopy
def create(cognitopy: CognitoPy, username: str, password: str):
    try:
        cognitopy.register(username=username, password=password)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("User registered successfully")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@click.option("--code", "-c", required=True, type=str)
@init_cognitopy
def confirm(cognitopy: CognitoPy, username: str, code):
    try:
        cognitopy.confirm_register(username=username, confirmation_code=code)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("User confirmed successfully")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@init_cognitopy
def resend_confirmation(cognitopy: CognitoPy, username: str):
    try:
        cognitopy.resend_confirmation_code(username=username)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("Confirmation code resent successfully")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@init_cognitopy
def delete(cognitopy: CognitoPy, username: str):
    try:
        cognitopy.admin_delete_user(username=username)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("User deleted successfully")
