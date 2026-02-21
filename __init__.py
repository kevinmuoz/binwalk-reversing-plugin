import logging

logging.getLogger(__name__).info("Initializing pybinwalk adapter...")

# Binary Ninja (GUI)
try:
    import binaryninjaui
    from . import binja
    binja._register()
except Exception:
    pass

# Cutter (TODO: add support for Cutter)
try:
    import cutter
    from . import cutter as module

    def create_cutter_plugin():
        return module.create_cutter_plugin()

except ImportError:
    pass
