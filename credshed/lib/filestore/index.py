#!/usr/bin/env python3

# by TheTechromancer

import re
import json
import logging
from .util import *
from pathlib import Path
from collections.abc import MutableMapping


# set up logging
log = logging.getLogger('credshed.filestore.index')


sha1_regex = re.compile(r'^[a-f0-9]{40}$', re.I)

def is_hash(s):
    if type(s) == str:
        if sha1_regex.match(s):
            return True
    return False



class FilestoreIndex(MutableMapping):
    '''
    Dictionary-like object which allows inverse lookups for hashes and filenames:
        index[hash] --> file
        index[file] --> hash
    '''

    def __init__(self, filestore_dir):

        self.dir = Path(filestore_dir).resolve()

        self.file = self.dir / 'index.json'

        # get filenames by hash
        self.hash_index = dict()
        # get hash by filename
        self.file_index = dict()


    def read(self):

        log.info(f'Reading filestore index from {self.file}')

        try:

            with open(self.file) as f:
                hash_index = json.load(f)
                for filehash, filenames in hash_index.items():
                    try:
                        self.add(self.dir / filenames['master_file'], filehash=filehash)
                        for child in filenames['child_files']:
                            self.add(self.dir / child, filehash)
                    except KeyError as e:
                        # if one of these keys is missing, something is wrong.
                        # purge the entire entry
                        log.warning(f'Index is missing key {e} missing for {filehash}')
                        continue
                log.info(f'Successfully read {len(self.hash_index):,} index entries')

        except (OSError, json.decoder.JSONDecodeError):
            log.error(f'Error reading index file {self.file}, starting fresh')
            return dict()


    def write(self):

        log.info(f'Writing filestore index to {self.file}')

        try:

            with open(str(self.file), 'w') as f:
                json.dump(self.json, f)
                log.info(f'Successfully wrote {len(self.hash_index):,} index entries')

        except OSError:
            log.error(f'Error writing index file {self.file}')
            return dict()


    def add(self, filename, filehash=None):
        '''
        Adds a file to the index and returns its master if it's already been added
        '''

        if filehash is None:
            filehash = self.hash(filename)

        filenames = list(self.indexify(filename))
        master = None

        # try adding the file to an existing entry
        try:
            master_filename = self.hash_index[filehash]['master_file']
            master = self.dir / master_filename
            # if the master file doesn't exist, it's clearly been moved
            if not filename.is_symlink() and not master.exists():
                log.info(f'File {master} has been moved to {filename}')
                index_filename = str(filename.relative_to(self.dir))
                # update the master_file to match its new location
                self.hash_index[filehash]['master_file'] = index_filename
                master_filename = index_filename

            # make sure we're not adding the master file as a child
            for filename in filenames:
                if not filename == master_filename:
                    self.hash_index[filehash]['child_files'].add(filename)

        except KeyError:
            # if that fails, make it master
            self.hash_index[filehash] = {
                # use the resolved filename (last in the list) if possible
                'master_file': filenames[-1],
                'child_files': set(filenames[:-1])
            }

        for filename in filenames:
            self.file_index[filename] = filehash

        return master


    @property
    def json(self):
        '''
        Returns self.hash_index with child_files converted to JSON-friendly list type
        '''
        json = dict()

        for filehash, filenames in self.hash_index.items():
            master_file = filenames['master_file']
            child_files = list(filenames['child_files'])
            json[filehash] = {
                'master_file': master_file,
                'child_files': list(child_files)
            }

        return json    


    def __getitem__(self, key):

        if is_hash(key):
            return self.hash_index[key]
        else:
            for f in self.indexify(key):
                try:
                    return self.file_index[f]
                except KeyError:
                    continue

        raise KeyError(key)


    def __delitem__(self, key):

        if is_hash(key):
            # only delete the hash_index entry
            # so we can still look up hash by filename
            del self.hash_index[key]
        else:
            filehash = self.file_index[key]


    def __setitem__(self):

        pass


    def __iter__(self):

        for filehash, filenames in list(self.hash_index.items()):
            master_file = self.dir / filenames['master_file']
            child_files = [self.dir / f for f in filenames['child_files']]
            yield (filehash, (master_file, child_files))


    def __len__(self):

        return len(self.hash_index)


    def __bool__(self):

        return bool(self.hash_index)


    def clear(self):

        self.hash_index.clear()
        self.file_index.clear()


    def __contains__(self, key):

        if is_hash(key):
            return key in self.hash_index
        else:
            return any([f in self.file_index for f in self.indexify(key)])


    def indexify(self, path):
        '''
        yields the index-able (relative to self.dir) path
        and then its "master" if it's a symlink
        '''
        paths = []
        path = Path(path)
        paths.append(path)
        if path != path.resolve():
            paths.append(path.resolve())

        for p in paths:
            yield str(p.relative_to(self.dir))


    def hash(self, filename):

        # try to get hash by filename
        try:
            return self[filename]
        except KeyError:
            pass

        # if that fails, hash it for the first time
        file_hash = hash_file(filename)
        # and add it to the file index so we won't need to hash it again
        for index_filename in self.indexify(filename):
            self.file_index[index_filename] = file_hash
        
        return file_hash