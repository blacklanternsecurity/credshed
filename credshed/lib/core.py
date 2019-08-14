#!/usr/bin/env python3.7

# by TheTechromancer

import os
import queue
import random
import logging
import threading
from .db import DB
from .leak import *
from .errors import *
from math import sqrt
import pymongo.errors
from time import sleep
from .quickparse import *
from datetime import datetime
from multiprocessing import cpu_count



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



class CredShed():

    def __init__(self, output='__db__', unattended=False, metadata=None, metadata_only=False, deduplication=False, threads=2):

        # if metadata = None, 
        self.metadata = metadata
        self.metadata_only = metadata_only

        try:
            self.db = DB(use_metadata=metadata, metadata_only=metadata_only)
        except pymongo.errors.ServerSelectionTimeoutError as e:
            raise CredShedTimeoutError('Connection to database timed out: {}'.format(str(e)))

        self.threads = threads
        self.output = Path(output)
        self.unattended = unattended
        self.deduplication = deduplication

        self.errors = []

        # overwrite output file
        if not self.output.name == '__db__':
            with open(str(self.output), 'w') as f:
                f.write('')

        self.STOP = False

        # set up logging
        log_file = '/var/log/credshed/credshed.log'
        log_level=logging.DEBUG
        log_format='%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s'
        try:
            logging.basicConfig(level=log_level, filename=log_file, format=log_format)
        except (PermissionError, FileNotFoundError):
            logging.basicConfig(level=log_level, filename='credshed.log', format=log_format)
            errprint('[!] Unable to create log file at {}, logging to current directory'.format(log_file))
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

        return self.db.stats(accounts=True, counters=True, sources=True, db=True)



    def import_files(self, files):
        '''
        takes a single file or directory, or a list of files/directories to import
        '''

        # make sure "files" is an iterable
        if type(files) == str or type(files) == Path:
            files = [files]

        to_add = set()
        # get recursive file listing
        for file in files:
            if file.is_file():
                to_add.add((file, None))
            elif file.is_dir():
                to_add.update(set(self._get_leak_files(file)))
            else:
                continue

        # if we're importing a lot of files, parallelize
        if len(to_add) > 1 and self.unattended and str(self.output) == '__db__':

            start_time = datetime.now()

            file_threads = max(1, int(self.threads / 2))
            self.threads = 2

            pool = [None] * file_threads
            self.log.info('{:,} files detected, adding in parallel ({} thread(s), {} process(es) per file)'.format(len(to_add), file_threads, self.threads))

            try:
                completed = 0
                for l in to_add:

                    if self.STOP:
                        break

                    while not self.STOP:
                        try:
                            for i in range(len(pool)):

                                try:
                                    if pool[i].is_alive():
                                        continue
                                    else:
                                        completed += 1
                                        time_elapsed = datetime.now() - start_time
                                        self.log.info('{:,}/{:,} ({:.1f}%) files completed in {}'.format(completed, len(to_add), (completed/len(to_add)*100), str(time_elapsed).split('.')[0]))

                                except AttributeError:
                                    pass
                                    
                                pool[i] = threading.Thread(target=self._add_by_file, name=str(l[1]), args=(l,))
                                pool[i].start()
                                # break out of infinite loop
                                assert False

                            sleep(.1)

                        except AssertionError:
                            break

                active_threads = []
                for t in pool:
                    try:
                        if t.is_alive():
                            active_threads.append(str(t))
                    except AttributeError:
                        continue

                self.log.info('Reached end, waiting for {:,} active threads to finish'.format(len(active_threads)))

                while not all([t is None for t in pool]):
                    for i in range(len(pool)):
                        if pool[i] is not None:
                            if not pool[i].is_alive():
                                completed += 1
                                time_elapsed = datetime.now() - start_time
                                self.log.info('{:,}/{:,} ({:.1f}%) files completed in {}'.format(completed, len(to_add), (completed/len(to_add)*100), str(time_elapsed).split('.')[0]))
                                pool[i] = None
                                continue
                            else:
                                self.log.debug('Waiting on thread {}'.format(pool[i].name))
                    sleep(1)

            except KeyboardInterrupt:
                self.STOP = True
                raise
            '''
            futures = []

            file_thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=file_threads)
            try:
                for l in to_add:
                    futures.append(file_thread_executor.submit(self._add_by_file, l))

                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    completed += 1
                    self.log.info('\n>> {:,} FILES COMPLETED <<\n'.format(completed))

            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
            finally:
                file_thread_executor.shutdown(wait=False)
            '''

        else:
            self.log.info('[+] {:,} files detected, importing using {} threads'.format(len(to_add), self.threads))

            for l in to_add:
                completed = 0
                start_time = datetime.now()

                file, _dir = l
                self.log.info('[+] Importing {}'.format(file))
    
                self._add_by_file(l)

                time_elapsed = datetime.now() - start_time
                self.log.info('>> {:,}/{:,} ({:.1f}%) files completed in {} <<'.format(completed, len(to_add), (completed/len(to_add)*100), str(time_elapsed).split('.')[0]))


        if self.unattended and self.errors:
            e = 'Errors encountered:\n\t'
            e += '\n\t'.join(self.errors)
            self.log.info(e)



    def delete_leak(self, source_id):

        self.db.delete_leak(int(source_id))




    def _add_by_file(self, dir_and_file, max_tries=5):
        '''
        takes iterable of directories and files in the format:
        [
            (leak_dir, leak_file)
            ...
        ]
        '''

        # initialize database

        while ( (not self.STOP) and (max_tries > 0) ):

            try:

                # if leak_file is None, assume leak_dir is just a standalone file
                if dir_and_file[1] is None:
                    leak_file = dir_and_file[0]
                    leak_friendly_name = leak_file.name
                else:
                    leak_dir, leak_friendly_name = dir_and_file
                    leak_file = leak_dir / leak_friendly_name

                db = DB(use_metadata=self.metadata, metadata_only=self.metadata_only)


                try:
                    q = QuickParse(file=leak_file, source_name=leak_friendly_name, unattended=self.unattended, strict=True)

                except QuickParseError as e:
                    self.log.warning('{}'.format(str(e)))
                    self.log.warning('{} falling back to non-strict mode'.format(leak_file))
                    q = QuickParse(file=leak_file, source_name=leak_friendly_name, unattended=self.unattended, strict=False)
                    #self.errors.append(e)
                    #self.errors.append(e2)

                except KeyboardInterrupt:
                    if self.unattended:
                        raise
                    else:
                        self.log.info('Skipping {}'.format(str(leak_file)))
                        return

                leak = Leak(q.source_name, q.source_hashtype, q.source_misc)

                # if we're writing to the database, handle duplicate source
                if self.output.name == '__db__':

                    try:
                        # see if source already exists
                        source_already_in_db = db.sources.find_one(leak.source.document(misc=False, date=False))

                        if source_already_in_db:
                            source_id, source_name = source_already_in_db['_id'], source_already_in_db['name']
                            if not self.unattended:
                                answer = input('Source ID {} ({}) already exists, merge? (Y/n)'.format(source_id, source_name)) or 'y'
                                if not answer.lower().startswith('y'):
                                    self.log.info('Skipping existing source ID {} ({})'.format(source_id, source_name))
                                    return
                                self.log.warning('Merging {} with existing source ID {} ({})'.format(leak_file, source_id, source_name))

                    except pymongo.errors.PyMongoError as e:
                        error = str(e)
                        try:
                            error += str(e.details)
                        except AttributeError:
                            pass
                        if error:
                            self.log.error(error)
                        self.STOP = True
                        break

                if not self.deduplication:
                    # override set with generator
                    leak.accounts = q.__iter__()

                else:
                    account_counter = 0
                    self.log.info('Deduplicating accounts')
                    for account in q:
                        if not self.STOP:
                            #self.log.info(str(account))
                            #try:
                            leak.add_account(account)
                            #except ValueError:
                            #    continue
                            account_counter += 1
                            if account_counter % 1000 == 0 and not self.unattended:
                                sys.stderr.write('\r[+] {:,} '.format(account_counter), end='')

                    if not self.unattended:
                        sys.stderr.write('\r[+] {:,}'.format(account_counter))
                    self.log.info('{:,} accounts deduplicated for {}'.format(account_counter, leak_file))


                if self.output.name == '__db__':

                    #print('\nAdding:\n{}'.format(str(leak)))
                    #file_thread_executor.submit(db.add_leak, leak, num_threads=options.threads)
                    #self.log.info('[{}] Calling db.add_leak()'.format(dir_and_file))
                    import_result = db.add_leak(leak, num_child_processes=self.threads)
                    #self.log.info('[{}] Finished calling db.add_leak()'.format(dir_and_file))

                else:
                    self.log.info('Writing leak {} to {}'.format(leak_file, str(self.output)))
                    # open file in append mode because we may be parsing more than one file
                    with open(str(self.output), 'ab') as f:
                        for account in leak:
                            #self.log.info(str(account))
                            f.write(account.bytes + b'\n')
                    #leak.dump()

            except QuickParseError as e:
                self.log.error('{}'.format(str(e)))
                break

            except CredShedDatabaseError as e:
                self.log.error(str(e))
                max_tries -= 1
                continue

            finally:
                try:
                    db.close()
                    # self.comms_queue.put('[+] Finished adding {}'.format(leak_file))
                except UnboundLocalError:
                    pass

            break


    def _get_leak_dirs(self, path):
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
                    for p in self._get_leak_dirs(path / d):
                        yield p
        except StopIteration:
            pass


    def _get_leak_files(self, path):
        '''
        takes directory
        yields:
        [
            (leak_dir, leak_file)
            ...
        ]

        each directory and file represent a full path when concatenated
            e.g.:
                leak_dir / leak_file
        '''

        leak_dirs = {}

        for d in self._get_leak_dirs(path):
            leak_files = []
            for dir_name, dir_list, file_list in os.walk(d):
                for file in file_list:
                    yield (d.parent, (Path(dir_name) / file).relative_to(d.parent))