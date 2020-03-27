#!/usr/bin/env python3

# by TheTechromancer

### MISC FUNCTIONS USED THROUGHOUT THE CODEBASE ###

import os
import sys
import logging
from .errors import *
from . import filestore
from pathlib import Path

log = logging.getLogger('credshed.util')


def clean_encoding(s):
    '''
    Given bytes, try to decode and re-encode
    If decoding fails, problematic characters are replaced with their hex code
    E.g. "Pass\\x66word"
    '''

    if type(s) == bytes:
        return decode(s).encode(encoding='utf-8')
    elif type(s) == str:
        return decode(s.encode(encoding='utf-8'))
    raise ValueError('Incorrect type passed to clean_encoding()')


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


def hash_file(filename):

    try:
        # if filestore is active, hash through the index in case it's already been cached
        return filestore.filestore.hash_file(filename)

    # otherwise, just dew it
    except (AttributeError, FilestoreHashError) as e:
        log.debug(e)
        f = filestore.Filestore()
        return f.hash_file(filename)


def size(filename):

    return filestore.util.size(filename)


def recursive_file_list(paths):
    '''
    accepts single or multiple files/directories
    yields filenames
    compressed = whether or not to include compressed files
    '''
    if not type(paths) == list:
        paths = [paths]

    paths = [Path(p).resolve() for p in paths]

    for path in paths:
        for file in filestore.util.list_files(path):
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