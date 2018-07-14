import os

path = os.path.join(__path__[0], 'version.py')
__version__ = eval(open(path).read())
__all__ = [ 'edgex_access', 'edgex_config', 'edgex_store', 'edgex_object', 'edgex_hasher', 'edgex_logger' ]

from .edgex_access import *
