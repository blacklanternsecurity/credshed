from ..errors import FilestoreError

from .filestore import *
try:
    filestore = Filestore()
except FilestoreError:
    pass
