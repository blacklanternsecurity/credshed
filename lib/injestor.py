#!/usr/bin/env python3

# by TheTechromancer

import logging
from .db import DB
from .errors import *
import multiprocessing
from time import sleep
from queue import Empty
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
        self.finished = False

        # queue for unique accounts
        self.result_queue = multiprocessing.Queue()



    def start(self, force=False):

        self.unique_accounts = 0
        import_finished = False

        if (not self.finished) or force:

            log.info(f'Adding source {self.source.filename} using {self.threads:,} threads')

            source = self.db.add_source(self.source)

            if source['import_finished'] is True and not force:
                log.warning(f'Import already finished for {self.source.filename}, skipping')

            else:

                try:

                    source_id = source['_id']
                    pool = [None] * self.threads
                    batch_counter = 1

                    for batch in self._gen_batches():
                        '''
                        upserted_accounts = self._injest(batch, source_id)
                        for a in upserted_accounts:
                            yield a
                        '''
                    
                        try:

                            # loop until batch has been submitted
                            while 1:

                                for unique_account in self.empty_result_queue():
                                    yield unique_account


                                #self.injest(batch, source_id, self.result_queue)
                                #assert False

                                # make sure processes are started
                                for i in range(len(pool)):
                                    process = pool[i]
                                    if process is None or not process.is_alive():
                                        if process is not None:
                                            log.debug(f'Injestor process #{i+1} has finished')
                                        pool[i] = multiprocessing.Process(target=self.injest, args=(batch, source_id, self.result_queue), daemon=True)
                                        log.info(f'Injesting batch #{batch_counter} - {self.total_accounts:,} total, {self.unique_accounts:,} unique')
                                        batch_counter += 1
                                        pool[i].start()
                                        # move on to next batch
                                        assert False

                                # prevent unnecessary CPU usage
                                sleep(.1)

                        except AssertionError:
                            continue

                    for unique_account in self.empty_result_queue():
                        yield unique_account

                    import_finished = True

                except KeyboardInterrupt:
                    log.warning('Stopping import')

                except Exception as e:
                    log.critical(e)

                finally:
                    log.info('Waiting for threads to finish')
                    # wait until all threads are stopped:
                    while 1:
                        finished_threads = [p is None or not p.is_alive() for p in pool]
                        if all(finished_threads):
                            break
                        else:
                            log.debug(f'Waiting for {finished_threads.count(False):,} threads to finish for {self.source.filename}')
                            sleep(1)

                        for unique_account in self.empty_result_queue():
                            yield unique_account

                    # update counters
                    self.db.add_source(self.source, import_finished=import_finished)
                    
                    if not import_finished:
                        raise KeyboardInterrupt

        else:
            log.error(f'Injestor for {self.source.filename} already finished')



    def empty_result_queue(self):

        # make sure the result queue is empty
        while 1:
            try:
                unique_accounts = self.result_queue.get_nowait()
                log.debug(f'{len(unique_accounts):,} unique accounts')
                try:
                    log.error('Database error encountered:\n    ' + '\n'.join([str(e) for e in unique_accounts['errors']]))
                except TypeError:
                    for unique_account in unique_accounts:
                        self.unique_accounts += 1
                        yield unique_account                
            except Empty:
                break


    @staticmethod
    def injest(batch, source_id, result_queue):

        try:

            with DB() as db:

                result_queue.put(db.add_accounts(batch, source_id))

                # required so that the queue's .put() call finishes
                sleep(.5)

        except KeyboardInterrupt:
            pass



    @staticmethod
    def _injest(batch, source_id):

        upserted_accounts = []

        with DB() as db:
            upserted_accounts = db.add_accounts(batch, source_id)

        return upserted_accounts



    def _gen_batches(self, batch_size=10000):
        '''
        Yields lists of simple "Account" dicts of length <batch_size>
        '''

        self.total_accounts = 0

        batch = []
        for account in self.source:
            self.total_accounts += 1
            self.source.increment(account)
            batch.append(account)

            if batch and ((self.source.total_accounts) % batch_size == 0):
                yield batch
                batch = []
            
        if batch:
            yield batch
