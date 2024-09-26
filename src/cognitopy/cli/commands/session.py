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
@click.option("--token", "-t", required=True, type=str)
@click.option("--refresh", "-r", required=True, type=str)
@init_cognitopy
def refresh(cognitopy: CognitoPy, token: str, refresh: str):
    try:
        token = cognitopy.renew_access_token(access_token=token, refresh_token=refresh)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo(f'New access_token = {token})')


@click.command()
@click.option("--token", "-t", required=True, type=str)
@init_cognitopy
def delete_user(cognitopy: CognitoPy, token: str):
    try:
        cognitopy.delete_user(access_token=token)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("User deleted successfully")


@click.command()
@click.option("--previous_password", "-prep", required=True, type=str)
@click.option("--proposed_password", "-prop", required=True, type=str)
@click.option("--token", "-t", required=True, type=str)
@init_cognitopy
def change_password(cognitopy: CognitoPy, previous_password: str, proposed_password: str, token: str):
    try:
        cognitopy.change_password(previous_password=previous_password, proposed_password=proposed_password,
                                  access_token=token)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("Password changed successfully")
