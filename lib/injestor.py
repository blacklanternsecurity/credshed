#!/usr/bin/env python3

# by TheTechromancer

import logging
from .db import DB
from . import logger
from .errors import *
from time import sleep
from queue import Empty
from .processpool import *
from datetime import datetime, timedelta


# set up logging
log = logging.getLogger('credshed.injestor')


class Injestor():
    '''
    Given a Source object, injests the contents into the database as fast as possible
    '''

    def __init__(self, source, threads=4):

        self.source = source
        self.threads = threads
        self.db = DB()


    def start(self, force=False):

        # call db.add_source for the first time to create it in the database
        source = self.db.add_source(self.source)

        if source['import_finished'] and not force:
            log.warning(f'Import already finished for {self.source.filename}, skipping')

        else:
            log.info(f'Adding source {self.source.filename} using {self.threads:,} threads')

            source_id = source['_id']

            if self.threads > 1:

                with ProcessPool(self.threads, name=self.source.filename) as pool:
                    for unique_accounts in pool.map(self.injest, self._gen_batches(), args=(source_id,)):
                        for unique_account in unique_accounts:
                            self.source.unique_accounts += 1
                            yield unique_account

            else:
                # don't use multiprocessing if there's only 1 thread
                for batch in self._gen_batches():
                    unique_accounts = self.injest(batch, source_id)
                    for unique_account in unique_accounts:
                        self.source.unique_accounts += 1
                        yield unique_account
                    
            # call db.add_source for the second time to update counters
            # or delete the source if it didn't contain anything
            self.db.add_source(self.source, import_finished=True)


    @staticmethod
    def injest(batch, source_id):

        try:

            with DB() as db:
                return db.add_accounts(batch, source_id)

        except KeyboardInterrupt:
            log.critical('Interrupted')

        except Exception as e:
            import traceback
            log.critical(traceback.format_exc())



    def _gen_batches(self, batch_size=7500):
        '''
        Yields lists of simple "Account" dicts of length <batch_size>

        1M, 1000 batch size, 8 processes on 4-core cpu: 3m44.828s
        1M, 5000 batch size, 8 processes on 4-core cpu: 2m20.733s
        1M, 7500 batch size, 8 processes on 4-core cpu: 2m13.390s
        1M, 10000 batch size, 8 processes on 4-core cpu: 2m17.838s
        '''

        batch = []
        for account in self.source:
            self.source.increment(account)
            batch.append(account)

            if batch and ((self.source.total_accounts) % batch_size == 0):
                log.debug(f'Submitting batch of {len(batch):,}')
                log.debug(f'{self.source.unique_accounts:,} unique accounts')
                log.debug(f'{self.source.total_accounts:,} total accounts')
                yield batch
                batch = []
            
        if batch:
            log.debug(f'Submitting batch of {len(batch):,}')
            log.debug(f'{self.source.unique_accounts:,} unique accounts')
            log.debug(f'{self.source.total_accounts:,} total accounts')
            yield batch
