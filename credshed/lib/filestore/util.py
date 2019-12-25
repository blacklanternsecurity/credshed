#!/usr/bin/env python3

# by TheTechromancer

import os
import hashlib
import configparser
from ..errors import *
from pathlib import Path


def hash_file(filename, blocksize=65536):
    '''
    return sha1 digest of file
    '''

    filename = Path(filename).resolve()

    file_hash = hashlib.sha1()

    try:
        with open(str(filename), 'rb') as f:
            block = f.read(blocksize)
            while len(block) > 0:
                file_hash.update(block)
                block = f.read(blocksize)

        return file_hash.hexdigest()

    except OSError as e:
        raise FilestoreHashError(f'Failed to hash file {filename}: {e}')



def write_metadata(filename, file_hash, master=None):

    try:
        with open(f'{filename}.filestore', 'w') as f:
            f.write('[FILESTORE]\n')
            f.write(f'filename={filename}\n')
            if master is not None:
                f.write(f'resolved={master}\n')
            f.write(f'infohash={file_hash}\n')
    except OSError as e:
        raise FilestoreMetadataError(f'Failed to read metadata for {filename}: {e}')


def read_metadata(filename): 

    try:
        metadata = configparser.ConfigParser()
        metadata.read(f'{filename}.filestore')
        orig_filename = metadata['FILESTORE']['filename']
        orig_hash = metadata['FILESTORE']['infohash']
        return (orig_filename, orig_hash)

    except (OSError, configparser.Error, KeyError) as e:
        raise FilestoreMetadataError(f'Failed to read metadata for {filename}: {e}')



def size(filename):
    '''
    Returns size of file in bytes
    '''

    filename = Path(filename).resolve()
    try:
        return os.stat(str(filename)).st_size
    except OSError as e:
        raise FilestoreUtilError(f'Error getting filesize from {filename}: {e}')