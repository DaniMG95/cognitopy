import click
from cognitopy import CognitoPy
from cognitopy.exceptions import ExceptionAuthCognito
from cognitopy.cli.commands import init_cognitopy


@click.command()
@click.option("name", "-n", required=True, type=str)
@click.option("description", "-d", required=True, type=str)
@click.option("precedence", "-p", required=True, type=int)
@click.option("role_arn", "-r", required=True, type=str)
@init_cognitopy
def create(cognitopy: CognitoPy, name: str, description: str, precedence: int, role_arn: str):
    try:
        cognitopy.admin_create_group(group_name=name, description=description, precedence=precedence, role_arn=role_arn)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("Group created successfully")


@click.command()
@click.option("name", "-n", required=True, type=str)
@click.option("group", "-g", required=True, type=str)
@init_cognitopy
def add_user(cognitopy: CognitoPy, name: str, group: str):
    try:
        cognitopy.admin_add_user_to_group(username=name, group_name=group)
    except ExceptionAuthCognito as e:
        click.echo(e)
    else:
        click.echo("User added to group successfully")
