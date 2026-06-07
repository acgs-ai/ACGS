"""Real provider adapters, imported lazily by the factory only when selected.

Each module depends on a third-party SDK declared as an optional extra in
pyproject. Importing this subpackage does not import those SDKs.
"""
