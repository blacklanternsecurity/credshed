import os
import logging
from pathlib import Path
from .decompress import is_compressed


log = logging.getLogger('credshed.filestore.util')


def delete_dir(dirname):
    '''
    Remove a directory if it's empty or only contains empty files
    '''

    try:
        dirname = Path(dirname).resolve()
        for file in list_files(dirname):
            if size(file) == 0:
                log.debug(f'Deleting empty file {file}')
                file.unlink()
        dirname.rmdir()

    except (OSError, PermissionError) as e:
        log.debug(f'Error deleting directory {dirname}')



def size(filename):
    '''
    Returns size of file in bytes
    '''

    filename = Path(filename).resolve()
    try:
        return os.stat(str(filename)).st_size
    except OSError as e:
        raise FilestoreUtilError(f'Error getting filesize from {filename}: {e}')



def list_files(path, include_symlinks=False):

    path = Path(path)

    if path.is_file():
        yield path

    else:
        for dir_name, dir_list, file_list in os.walk(path, followlinks=False):
            log.debug(f'Found dir: {dir_name}')
            for f in file_list:
                file = Path(dir_name) / f
                if include_symlinks or not file.is_symlink():
                    yield file