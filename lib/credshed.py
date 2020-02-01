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
log = logging.getLogger('credshed')



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



    def search(self, query, query_type='email', limit=0):
        '''
        query = search string(s)
        yields Account objects
        '''

        for account in self.db.search(str(query), query_type=query_type, limit=limit):
            #print('{}:{}@{}:{}:{}'.format(result['username'], result['email'], result['domain'], result['password'], result['misc']))
            yield account



    def count(self, query, query_type='email'):

        return self.db.count(query, query_type)



    def db_stats(self):

        return self.db.stats(accounts=True, sources=True, db=True)


    def query_stats(self, query, query_type='domain', limit=10):

        # go get the raw data (source_id: num_accounts)
        stats = self.db.query_stats(query, query_type)
        stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:limit]

        return stats


    def get_source(self, source_id):

        return self.db.get_source(source_id)


    def delete_source(self, source_id):

        self.db.delete_source(int(source_id))



    def import_file(self, filename, strict=False, unattended=True, threads=2, show=False, force=False):
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
                for unique_account in injestor.start(force=force):
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