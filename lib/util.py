# by TheTechromancer

### MISC FUNCTIONS USED THROUGHOUT THE CODEBASE ###

import sys
import logging
from .errors import *
from time import sleep
from . import filestore
from pathlib import Path

log = logging.getLogger('credshed.util')


def encode(s):

    try:
        return s.encode(encoding='utf-8')
    except UnicodeEncodeError:
        return ''


def decode(b):

    try:
        return b.decode(encoding='utf-8')
    except UnicodeDecodeError:
        return str(b)[2:-1]


def errprint(*s, end='\n'):

    sys.stderr.write(' '.join([str(i) for i in s]) + end)
    sys.stderr.flush()


def error_detail(e):
    '''
    Given a pymongo error, returns a string containing as much detail as possible
    '''
    error = f'{e}: '
    try:
        error += str(e.details)
    except AttributeError:
        pass
    return error


def number_range(s):
    '''
    takes array of strings and tries to convert into an array of ints
    '''

    n_array = set()

    for a in s:
        for r in a.split(','):
            try:
                if '-' in r:
                    start, end = [int(i) for i in r.split('-')[:2]]
                    n_array = n_array.union(set(list(range(start, end+1))))
                else:
                    n_array.add(int(r))

            except (IndexError, ValueError):
                sys.stderr.write('[!] Error parsing source ID "{}"'.format(a))
                continue

    return n_array


def recursive_file_list(paths, min_size=6):
    '''
    accepts single or multiple files/directories
    yields file objects
    '''

    if not type(paths) == list:
        paths = [paths]

    paths = [Path(p).resolve() for p in paths]

    for path in paths:

        log.info(f'Finding files in {path}')
        files = list(filestore.util.list_files(path))
        log.info(f'Found {len(files):,} files in {path}')

        average_file_size = bytes_to_human(sum([file.size for file in files]) / len(files))
        log.info(f'Average file size: {average_file_size}')

        for i, file in enumerate(files):

            # check size
            if file.size < min_size:
                log.debug(f'Skipping tiny/empty file "{file}"')
                continue

            yield file


def bytes_to_human(_bytes):
    '''
    converts bytes to human-readable filesize
    e.g. 1024 --> 1KB
    '''

    sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB']
    units = {}
    count = 0
    for size in sizes:
        units[size] = pow(1024, count)
        count +=1

    for size in sizes:
        if abs(_bytes) < 1024.0:
            if size == sizes[0]:
                _bytes = str(int(_bytes))
            else:
                _bytes = '{:.2f}'.format(_bytes)
            return '{}{}'.format(_bytes, size)
        _bytes /= 1024

    raise ValueError



class FileLock:
    '''
    Implements a simple sempahore using the filesystem
    '''
    def __init__(self, name='/tmp/credshed.lock'):

        self.file = Path(name).resolve()
        self.interval = .1


    def __enter__(self):

        while 1:
            if not self.file.is_file():
                with open(self.file, 'w') as f:
                    break
            else:
                sleep(self.interval)
                continue

        return self


    def __exit__(self, exception_type, exception_value, traceback):

        self.file.unlink()
