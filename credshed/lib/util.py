#!/usr/bin/env python3

# by TheTechromancer

### MISC FUNCTIONS USED THROUGHOUT THE PROJECT ###

import sys
from . import filestore


def clean_encoding(s):

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
        return filestore.filestore.index.hash(filename)

    # otherwise, just dew it
    except AttributeError:
        return filestore.util.hash_file(filename)


def size(filename):

    return filestore.util.size(filename)