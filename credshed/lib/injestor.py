#!/usr/bin/env python3

# by TheTechromancer

import logging
from .db import DB
from .errors import *
from datetime import datetime, timedelta





class Injestor():

    def __init__(self, source, threads=4):

        # set up logging
        self.log = logging.getLogger('credshed.injestor')

        self.source = source

        self.threads = threads

        self.db = DB()


    def injest(self):

        start_time = datetime.now()

        self.start()

        end_time = datetime.now()
        time_elapsed = (end_time - start_time).total_seconds()

        if self.source.total_accounts > 0:
            self.log.info('{:,}/{:,} ({:.2f}%) unique accounts in "{}".  Time elapsed: {:02d}:{:02d}:{:02d}'.format(
                self.source.unique_accounts,
                self.source.total_accounts,
                ((self.source.unique_accounts/self.source.total_accounts)*100), 
                self.source.filename,
                # // == floor division
                int(time_elapsed // 3600),
                int((time_elapsed % 3600) // 60),
                int(time_elapsed % 60)
            ))


    def start(self):

        self.log.debug('Adding source {}'.format(str(self.source)))

        source_id = self.db.add_source(self.source)

        self.log.debug('Using {} child threads'.format(self.threads))

        unique_accounts = dict()

        batches = self._gen_batches()
        for batch in batches:
            with DB() as db:
                upserted_accounts = db.add_accounts(batch, source_id)
                unique_accounts.update(upserted_accounts)
                self.source.unique_accounts += len(upserted_accounts)

        # update counters
        self.db.add_source(self.source, import_finished=True)

        return unique_accounts





    def _gen_batches(self, batch_size=10000):
        '''
        Yields lists of simple "Account" dicts of length <batch_size>
        '''

        batch = []
        for account in self.source:
            batch.append(account)
            self.source.total_accounts += 1

            if batch and ((self.source.total_accounts) % batch_size == 0):
                yield batch
                batch = []
            
        if batch:
            yield batch
