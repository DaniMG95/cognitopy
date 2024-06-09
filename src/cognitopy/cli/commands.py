import click


@click.command()
def hola():
    """Imprime un mensaje de saludo."""
    click.echo("¡Hola!")
