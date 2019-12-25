#!/usr/bin/env python3

# by TheTechromancer

import os
import sys
import logging
import threading
from .db import DB
from .util import *
from .errors import *
from .parser import *
from .source import *
import pymongo.errors
from time import sleep
from queue import Queue
from datetime import datetime
from .injestor import Injestor



class CredShed():
    '''
    Main class for interacting with credshed
    Contains useful methods such as:
        .search()
        .import()
        ...
    '''

    def __init__(self, stdout=False, unattended=False, deduplication=False, threads=2):

        self.stdout = stdout

        try:
            self.db = DB()
        except pymongo.errors.ServerSelectionTimeoutError as e:
            raise CredShedTimeoutError(f'Connection to database timed out: {e}')

        self.threads = threads
        self.unattended = unattended
        self.deduplication = deduplication

        self.errors = []

        self.STOP = False

        # set up logging
        log_file = '/var/log/credshed/credshed.log'
        log_level=logging.DEBUG
        log_format='%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s'
        try:
            logging.basicConfig(level=log_level, filename=log_file, format=log_format)
        except (PermissionError, FileNotFoundError):
            logging.basicConfig(level=log_level, filename='credshed.log', format=log_format)
            errprint(f'[!] Unable to create log file at {log_file}, logging to current directory')
        self.log = logging.getLogger('credshed')
        self.log.setLevel(log_level)



    def search(self, query, query_type='email', limit=0, verbose=False):
        '''
        query = search string(s)
        yields Account objects
        '''

        if type(query) == str:
            query = [query]

        num_results = 0
        for query in query:
            num_results += 1

            if limit > 0 and num_results > limit:
                break

            try:
                for account in self.db.search(str(query), query_type=query_type, max_results=limit):
                    #print('{}:{}@{}:{}:{}'.format(result['username'], result['email'], result['domain'], result['password'], result['misc']))

                    if verbose:
                        self.db.fetch_account_metadata(account)

                    yield account

            except pymongo.errors.OperationFailure as e:
                raise CredShedError('Error querying MongoDB: {}'.format(str(e)))



    def stats(self):

        return self.db.stats(accounts=True, sources=True, db=True)



    def delete_source(self, source_id):

        self.db.delete_source(int(source_id))



    def import_file(self, filename):

        source = Source(filename)
        source.parse(unattended=self.unattended)

        if self.stdout:
            for account in source:
                sys.stdout.buffer.write(account.bytes + b'\n')

        else:

            try:
                injestor = Injestor(source, threads=self.threads)
                injestor.injest()

            except KeyboardInterrupt:
                if self.unattended:
                    raise
                else:
                    self.log.info(f'Skipping {filename}')
                    try:
                        sleep(1)
                    except KeyboardInterrupt:
                        self.log.info(f'Cancelling import')
                        raise
                    return



    def _get_source_dirs(self, path):
        '''
        takes directory
        walks tree, stops walking and yields directory when it finds a file
        '''

        path = Path(path).resolve()
        try:
            dir_name, dir_list, file_list = next(os.walk(path))
            if file_list:
                #print(' - ', str(path))
                yield path
            else:
                for d in dir_list:
                    for p in self._get_source_dirs(path / d):
                        yield p
        except StopIteration:
            pass


    def _get_source_files(self, path):
        '''
        takes directory
        yields:
        [
            (source_dir, source_file)
            ...
        ]

        each directory and file represent a full path when concatenated
            e.g.:
                source_dir / source_file
        '''

        source_dirs = {}

        for d in self._get_source_dirs(path):
            source_files = []
            for dir_name, dir_list, file_list in os.walk(d):
                for file in file_list:
                    yield (d.parent, (Path(dir_name) / file).relative_to(d.parent))
