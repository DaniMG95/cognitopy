import click
from cognitopy.cli.commands import hola


@click.group()
def cli():
    pass


cli.add_command(hola)
