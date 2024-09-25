import click
from cognitopy import CognitoPy
from cognitopy.exceptions import ExceptionAuthCognito
from cognitopy.cli.commands import init_cognitopy


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


@click.command()
@click.option("--username", "-u", required=True, type=str)
@click.option("--password", "-p", required=True, type=str)
@init_cognitopy
def register(cognitopy: CognitoPy, username: str, password: str):
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
def confirm_register(cognitopy: CognitoPy, username: str, code):
    try:
        cognitopy.confirm_register(username=username, confirmation_code=code)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("User confirmed successfully")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@init_cognitopy
def resend_confirmation_code(cognitopy: CognitoPy, username: str):
    try:
        cognitopy.resend_confirmation_code(username=username)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("Confirmation code resent successfully")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@init_cognitopy
def forgot_password(cognitopy: CognitoPy, username: str):
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
def confirm_forgot_password(cognitopy: CognitoPy, username: str, code: str, new_password: str):
    try:
        cognitopy.confirm_forgot_password(username=username, confirmation_code=code, password=new_password)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("Password reset successfully")


@click.command()
@click.option("--username", "-u", required=True, type=str)
@init_cognitopy
def delete_user(cognitopy: CognitoPy, username: str):
    try:
        cognitopy.admin_delete_user(username=username)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("User deleted successfully")
