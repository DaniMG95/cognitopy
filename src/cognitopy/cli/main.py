import click
from cognitopy.cli.commands import init
from cognitopy.cli.commands.user import login


@click.group()
def cli():
    pass


@cli.group()
def user():
    """Comandos relacionados con el usuario."""
    pass


@cli.group()
def group():
    """Comandos relacionados con el usuario."""
    pass


@cli.group()
def password():
    """Comandos relacionados con el usuario."""
    pass


@cli.group()
def session():
    """Comandos relacionados con el usuario."""
    pass


@cli.group()
def user_maintenance():
    """Comandos relacionados con el usuario."""
    pass


cli.add_command(init)
user.add_command(login)
