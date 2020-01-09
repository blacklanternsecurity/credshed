#!/usr/bin/env python3

# by TheTechromancer

import sys
import logging
from .db import DB
from .errors import *
from .source import *
import pymongo.errors
from time import sleep
from .injestor import Injestor


# set up logging
log_format='%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s'
log = logging.getLogger('credshed')
log.setLevel(logging.DEBUG)



def set_log_file(filename='credshed.log'):

    try:
        log_filename = str(Path('/var/log/credshed') / filename)
        logging.basicConfig(level=log_level, filename=log_filename, format=log_format)
    except (PermissionError, FileNotFoundError):
        log.warning(f'Unable to create log file at {log_file}, logging to current directory')
        logging.basicConfig(level=log_level, filename='credshed.log', format=log_format)



class CredShed():
    '''
    Main class for interacting with credshed
    Contains useful methods such as:
        .search()
        .import()
        ...
    '''

    def __init__(self, stdout=False):

        self.stdout = stdout

        try:
            self.db = DB()
        except pymongo.errors.ServerSelectionTimeoutError as e:
            raise CredShedTimeoutError(f'Connection to database timed out: {e}')

        self.STOP = False



    def search(self, query, query_type='email', limit=None):
        '''
        query = search string(s)
        yields Account objects
        '''

        if type(query) == str:
            query = [query]

        if limit is None:
            left = 0
        else:
            log.info(f'Limiting to {limit:,} results')
            left = int(limit)

        for query in query:

            if limit and left <= 0:
                break

            try:
                for account in self.db.search(str(query), query_type=query_type, max_results=left):
                    #print('{}:{}@{}:{}:{}'.format(result['username'], result['email'], result['domain'], result['password'], result['misc']))
                    if limit:
                        if left <= 0:
                            break
                        left -= 1

                    yield account

            except pymongo.errors.OperationFailure as e:
                raise CredShedError('Error querying MongoDB: {}'.format(str(e)))



    def stats(self):

        return self.db.stats(accounts=True, sources=True, db=True)



    def delete_source(self, source_id):

        self.db.delete_source(int(source_id))



    def import_file(self, filename, strict=False, unattended=True, threads=2, show=False):
        '''
        Takes a filename as input
        Returns a two-tuple: (unique_accounts, total_accounts)

        show = whether or not to print unique accounts
        '''

        source = Source(filename)
        # make sure the file is readable
        try:
            source.hash
        except FilestoreHashError:
            log.error(f'Failure reading {filename}')
            return (0, 0)

        source.parse(unattended=unattended)

        if self.stdout:
            for account in source:
                sys.stdout.buffer.write(account.bytes + b'\n')

        else:

            try:
                injestor = Injestor(source, threads=threads)
                for unique_account in injestor.start():
                    source.unique_accounts += 1
                    if show:
                        print(unique_account)


            except KeyboardInterrupt:
                if unattended:
                    raise
                else:
                    log.info(f'Skipping {filename}')
                    try:
                        sleep(1)
                    except KeyboardInterrupt:
                        log.info(f'Cancelling import')
                        raise
                    return (0, 0)

        return (source.unique_accounts, source.total_accounts)