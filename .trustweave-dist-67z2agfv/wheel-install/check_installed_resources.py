from importlib.resources import files
from trustweave import __version__
resources = files('trustweave').joinpath('schemas')
assert any(item.name.endswith('.schema.json') for item in resources.iterdir())
print(__version__)
