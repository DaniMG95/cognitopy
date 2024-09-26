# flake8: noqa
import click
from cognitopy.cli.commands import init
from cognitopy.cli.commands import user, group, password, session, user_maintenance
import inspect


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

user_commands = [func for _, func in inspect.getmembers(user, inspect.isfunction)]
group_commands = [func for _, func in inspect.getmembers(group)]
password_commands = [func for _, func in inspect.getmembers(password)]
session_commands = [func for _, func in inspect.getmembers(session)]
user_maintenance_commands = [func for _, func in inspect.getmembers(user_maintenance)]

for func in user_commands:
    user.add_command(func)
for func in group_commands:
    group.add_command(func)
for func in session_commands:
    session.add_command(func)
