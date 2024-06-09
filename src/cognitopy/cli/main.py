import click
from cognitopy.cli.commands import hola


@click.group()
def cli():
    pass


cli.add_command(hola)


def run():
    cli()


if __name__ == "__main__":
    cli()
