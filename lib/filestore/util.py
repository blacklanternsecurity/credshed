import os
import magic
import logging
from pathlib import Path
from ..parser import File


log = logging.getLogger('credshed.filestore.util')


def delete_dir(dirname):
    '''
    Remove a directory if it's empty or only contains empty files
    '''

    try:
        dirname = Path(dirname).resolve()
        for file in list_files(dirname):
            if file.size == 0:
                log.debug(f'Deleting empty file {file}')
                file.unlink()
        dirname.rmdir()

    except (OSError, PermissionError) as e:
        log.debug(f'Error deleting directory {dirname}')


def list_files(path, include_symlinks=False):

    path = Path(path)
    log.info(f'Finding files in {path}')

    if path.is_file():
        yield File(path)

    elif path.is_dir():
        for dir_name, dir_list, file_list in os.walk(path, followlinks=False):
            #log.debug(f'Found dir: {dir_name}')
            for f in file_list:
                file = File(Path(dir_name) / f)
                if file.is_file() or (include_symlinks and file.is_symlink()):
                    yield file
                else:
                    log.debug(f'Not a file: {file}')

    else:
        log.warning(f'Unable to list files in {path}')



supported_compressions = [
    # magic string      # command for decompression
    ('microsoft excel',     ['ssconvert', '-S', '{filename}', '{extract_dir}/%s.csv']),
    ('rar archive',         ['unrar', 'x', '-o+', '-p-', '{filename}', '{extract_dir}/']),
    ('tar archive',         ['tar', '--overwrite', '-xvf', '{filename}', '-C', '{extract_dir}/']),
    ('gzip compressed',     ['tar', '--overwrite', '-xvzf', '{filename}', '-C', '{extract_dir}/']),
    ('gzip compressed',     ['gunzip', '--force', '--keep', '{filename}']),
    ('bzip2 compressed',    ['tar', '--overwrite', '-xvjf', '{filename}', '-C', '{extract_dir}/']),
    ('xz compressed',       ['tar', '--overwrite', '-xvJf', '{filename}', '-C', '{extract_dir}/']),
    ('lzma compressed',     ['tar', '--overwrite', '--lzma', '-xvf', '{filename}', '-C', '{extract_dir}/']),
    ('7-zip archive',       ['7z', 'x', '-p""', '-aoa', '{filename}', '-o{extract_dir}/']),
    ('zip archive',         ['7z', 'x', '-p""', '-aoa', '{filename}', '-o{extract_dir}/']),
]