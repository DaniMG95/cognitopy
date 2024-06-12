import click
from cognitopy.cli.commands import check_expired_token, init, login


@click.group()
def cli():
    pass


cli.add_command(check_expired_token)
cli.add_command(init)
cli.add_command(login)
