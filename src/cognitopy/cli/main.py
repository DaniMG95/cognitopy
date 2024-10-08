# flake8: noqa
import click
from cognitopy.cli.commands import init
from cognitopy.cli.commands import user as user_commands
from cognitopy.cli.commands import group as group_commands
from cognitopy.cli.commands import password as password_commands
from cognitopy.cli.commands import session as session_commands
from cognitopy.cli.commands import user_maintenance as user_maintenance_commands


@click.group()
def cli():
    pass


@cli.group()
def user():
    """User-related commands."""
    pass


@cli.group()
def group():
    """Group-related commands."""
    pass


@cli.group()
def password():
    """Password-related commands."""
    pass


@cli.group()
def session():
    """Session-related commands."""
    pass


@cli.group()
def user_maintenance():
    """User Maintenance-related commands."""
    pass


cli.add_command(init)
commands_by_group = {
    user: user_commands,
    group: group_commands,
    password: password_commands,
    session: session_commands,
    user_maintenance: user_maintenance_commands
}

for group, commands in commands_by_group.items():
    for name, cmd in commands.__dict__.items():
        if isinstance(cmd, click.Command):
            group.add_command(cmd)
