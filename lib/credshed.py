#!/usr/bin/env python3

# by TheTechromancer

import logging
from .db import DB
from .errors import *
from .source import *
from time import sleep


# set up logging
log = logging.getLogger('credshed')



class CredShed():
    '''
    Main class for interacting with credshed
    Contains useful methods such as:
        .search()
        .import_file()
        ...
    '''

    def __init__(self):

        self._db = None


    @property
    def db(self):

        if self._db is None:
            self._db = DB()
        return self._db
    


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


    def drop(self):

        self.db.drop()


    def query_stats(self, query, query_type='domain', limit=100):

        # go get the raw data (source_id: num_accounts)
        stats = self.db.query_stats(query, query_type)
        # sort and truncate it
        stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:limit]

        return stats


    def get_source(self, source_id):

        return self.db.get_source(source_id)


    def delete_source(self, source_id):

        self.db.delete_source(int(source_id))



    def import_file(self, filename, unattended=True, force=False, stdout=False, force_ascii=False):
        '''
        Takes a filename as input
        Returns a Source() object containing stats such as total accounts

        Source(filename) --> Source.parse() --> db.add_accounts(source)
        '''

        log.info(f'Parsing file "{filename}"')

        start_time = datetime.now()

        source = Source(filename)
        # make sure the file is readable
        if unattended and not stdout:
            try:
                source.hash
            except FilestoreHashError:
                log.error(f'Failure reading {filename}')
                return (0, 0)

        source.parse(unattended=unattended, force_ascii=force_ascii)

        if stdout:
            for account in source:
                print(str(account))

        else:

            try:
                self.db.add_accounts(source, force=force)

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


        end_time = datetime.now()
        time_elapsed = (end_time - start_time).total_seconds()

        if source.total_accounts > 0:
            log.info('{:,}/{:,} ({:.2f}%) new accounts in "{}"  Time elapsed: {:02d}:{:02d}:{:02d}'.format(
                source.unique_accounts,
                source.total_accounts,
                ((source.unique_accounts / source.total_accounts) * 100), 
                filename,
                # // == floor division
                int(time_elapsed // 3600),
                int((time_elapsed % 3600) // 60),
                int(time_elapsed % 60)
            ))

        return (source.unique_accounts, source.total_accounts)
