from ..errors import FilestoreError

from .filestore import *
from . import util
try:
    filestore = Filestore()
except FilestoreError:
    pass
