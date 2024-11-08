import click
from cognitopy.cli.config.config import Config
from cognitopy.exceptions import ExceptionCLIValidateConfig


@click.command()
def list():
    projects = Config.get_projects()
    click.echo("Projects:")
    for project in projects:
        click.echo(f" - {project}")


@click.command()
def current():
    click.echo(f"Current project: {Config().name}")


@click.command()
@click.argument("name", type=str)
def set(name: str):
    try:
        Config.set_name(name)
    except ExceptionCLIValidateConfig as e:
        click.echo(e)
    else:
        click.echo(f"Set current project to {name}")


@click.command()
@click.argument("name", type=str)
def get(name: str):
    try:
        config = Config(name=name)
        click.echo(f"Config {name}: ")
        properties_dict = {attr: getattr(config, attr) for attr in dir(config)
                           if isinstance(getattr(type(config), attr, None), property) and attr != "name"}
        for key, value in properties_dict.items():
            click.echo(f" - {key}: {value}")
    except ExceptionCLIValidateConfig as e:
        click.echo(e)


@click.command()
@click.argument("name", type=str)
def delete(name: str):
    try:
        Config.delete(name)
    except ExceptionCLIValidateConfig as e:
        click.echo(e)
    else:
        click.echo(f"Deleted config {name}")


@click.command()
@click.argument("name", type=str)
@click.option("key", "-k", type=str, required=True)
@click.option("value", "-v", type=str, required=True)
def edit(name: str, value: str, key: str):
    try:
        Config.edit(name=name, field=key, value=value)
    except ExceptionCLIValidateConfig as e:
        click.echo(e)
    else:
        click.echo(f"Edited config {name}")
