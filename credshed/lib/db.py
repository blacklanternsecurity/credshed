#!/usr/bin/env python3.7

# by TheTechromancer

import copy
import time
import queue
import hashlib
import logging
import pymongo
import traceback
import configparser
from .leak import *
from .util import *
from .errors import *
from time import sleep
import multiprocessing
from pathlib import Path
import concurrent.futures
from subprocess import run, PIPE


class DB():

    def __init__(self, use_metadata=True, metadata_only=False):

        self.metadata_only = metadata_only
        self.config = self.parse_config()

        try:

            ### MONGO PRIMARY ###

            try:
                main_server = self.config['MONGO PRIMARY']['server']
                main_port = int(self.config['MONGO PRIMARY']['port'])
                main_db = self.config['MONGO PRIMARY']['db']
                self.mongo_user = self.config['GLOBAL']['user']
                self.mongo_pass = self.config['GLOBAL']['pass']
            except KeyError as e:
                raise CredShedConfigError(str(e))

            # main DB
            self.main_client = pymongo.MongoClient(main_server, main_port, username=self.mongo_user, password=self.mongo_pass)
            self.main_db = self.main_client[main_db]
            try:
                self.main_db.command('dbstats')
            except ValueError as e:
                raise CredShedConfigError(str(e))

            self.accounts = self.main_db.accounts

        except pymongo.errors.PyMongoError as e:
            error = str(e) + '\n'
            try:
                error += str(e.details)
            except AttributeError:
                pass
            raise CredShedDatabaseError(error)

        self.use_metadata = False
        if use_metadata:
            try:

                ### MONGO METADATA ###

                try:
                    meta_server = self.config['MONGO METADATA']['server']
                    meta_port = int(self.config['MONGO METADATA']['port'])
                    meta_db = self.config['MONGO METADATA']['db']
                except KeyError as e:
                    raise CredShedConfigError(str(e))

                # meta DB (account metadata including source information, counters, leak <--> account associations, etc.)
                self.meta_client = pymongo.MongoClient(meta_server, meta_port, username=self.mongo_user, password=self.mongo_pass)
                self.meta_db = self.meta_client[meta_db]
                try:
                    self.meta_db.command('dbstats')
                except ValueError as e:
                    raise CredShedConfigError(str(e))

                self.account_tags = self.meta_db.account_tags
                self.use_metadata = True

            except pymongo.errors.PyMongoError as e:
                error = str(e) + '\n'
                try:
                    error += str(e.details)
                except AttributeError:
                    pass

                self.log.warning('Problem with metadata database at {}:{}\n{}'.format(\
                    meta_server, meta_port, error))

        if (not self.use_metadata) and self.metadata_only:
            raise CredShedMetadataError('"metadata_only" option specified but none is available')

        #self.accounts.create_index([('username', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('email', pymongo.ASCENDING)], sparse=True, background=True)

        # sources
        self.sources = self.main_db.sources
        # counters
        self.counters = self.main_db.counters

        # leak-specific counters
        self.leak_unique = 0
        self.leak_overall = 0
        self.leak_size = 0

        # set up logging
        self.log = logging.getLogger('credshed.db')


    def search(self, keywords, query_type='email', max_results=10000):
        '''
        ~ 2 minutes to regex-search non-indexed 100M-entry DB
        '''

        query_type = str(query_type).strip().lower()

        if type(keywords) == str:
            keywords = [keywords,]

        results = dict()

        for keyword in keywords:
            '''
            
            main_keyword = '^{}'.format(keyword)
            domain_keyword = '^{}'.format(keyword[::-1].lower())
            if password:
                results['passwords'] = self.accounts.find({'password': {'$regex': main_keyword, '$options': 'i'}})
            elif misc:
                results['descriptions'] = self.accounts.find({'misc': {'$regex': main_keyword}})
            elif Account.is_email(keyword):
                # email, domain = keyword.lower().split('@')[:2]
                # #results['emails'] = self.accounts.find({'$and': [{'email': email}, {'domain': {'$regex': domain_keyword}}]})
                # domain_keyword = base64.b64encode(sha1(b'.'.join(keyword.lower().encode().split(b'.')[-2:])).digest()).decode()[:6]
                # domain_regex = r'^{}.*'.format(domain_keyword).replace('+', r'\+')
                # results['emails'] = self.accounts.find({'$and': [{'email': email}, {'_id': {'$regex': domain_regex}}]}):

            else:
                #results['usernames'] = self.accounts.find({'username': {'$regex': main_keyword}}, collation=Collation(locale='en', strength=2))
                results['usernames'] = self.accounts.find({'username': {'$regex': main_keyword, '$options': 'i'}})
                results['emails'] = self.accounts.find({'$or': [{'email': {'$regex': main_keyword.lower()}}, {'domain': {'$regex': domain_keyword}}]})
                #print(self.accounts.find({'email': {'$regex': main_keyword}}).hint([('email', 1)]).explain())
                #results['emails'] = self.accounts.find({'email': {'$regex': main_keyword}})
            '''

            if query_type == 'email':
                try:
                    # _id begins with reversed domain
                    email, domain = keyword.lower().split('@')[:2]
                    domain_chunk = re.escape(domain[::-1])
                    email_hash = decode(base64.b64encode(hashlib.sha256(encode(email)).digest()[:6]))
                    query_str = domain_chunk + '\\|' +  email_hash

                    query_regex = r'^{}.*'.format(query_str)
                    query = {'_id': {'$regex': query_regex}}
                    self.log.info('Raw mongo query: {}'.format(str(query)))
                    results['emails'] = self.accounts.find(query).limit(max_results)
                    #results['emails'] = self.accounts.find({'email': email, '_id': {'$regex': domain_regex}})
                    #results['emails'] = self.accounts.find({'email': email})

                except ValueError:
                    raise CredShedError('Invalid email')
                    # assume email without domain
                    '''
                    email = r'^{}$'.format(keyword.lower())
                    query = {'email': {'$regex': email}}
                    self.log.info(query)
                    results['emails'] = self.accounts.find(query).limit(max_results)
                    '''


            elif query_type == 'domain':
                domain = keyword.lower()
                domain = re.escape(domain[::-1])

                if domain.endswith('.'):
                    # if query is like ".com"
                    query_regex = r'^{}[\w.]*\|'.format(domain)
                else:
                    # or if query is like "example.com"
                    query_regex = r'^{}[\.\|]'.format(domain)

                num_sections = len(domain.split('.'))
                query = {'_id': {'$regex': query_regex}}
                self.log.info('Raw mongo query: {}'.format(str(query)))
                results['emails'] = self.accounts.find(query).limit(max_results)

            elif query_type == 'username':
                query_regex = r'^{}$'.format(re.escape(keyword))
                query = {'username': {'$regex': query_regex}}
                self.log.info('Raw mongo query: {}'.format(str(query)))
                results['usernames'] = self.accounts.find(query).limit(max_results)

            else:
                raise CredShedError('Invalid query type: {}'.format(str(query_type)))

            for category in results:
                for result in results[category]:
                    try:
                        account = Account.from_document(result)
                        yield account
                    except AccountCreationError as e:
                        self.log.warning('{}'.format(str(e)))
            


    def fetch_account_metadata(self, account):

        if not self.use_metadata:
            raise CredShedMetadataError('No metadata available')

        sources = []

        if account is not None:

            try:

                _id = ''
                if type(account) == str:
                    _id = account
                elif type(account) == Account:
                    _id = account._id
                else:
                    raise TypeError

                source_ids = self.account_tags.find_one({'_id': _id})['s']

                for source_id in source_ids:
                    try:
                        sources.append(self.get_source(source_id))
                    except CredShedDatabaseError:
                        self.log.warning('No database entry found for source ID {}'.format(str(source_id)))
                        continue

            except KeyError as e:
                raise CredShedError('Error retrieving source IDs from account "{}": {}'.format(str(_id), str(e)))
            except TypeError as e:
                self.log.debug('No source IDs found for account ID "{}": {}'.format(str(_id), str(e)))

            account_metadata = AccountMetadata(sources)
            return account_metadata



    def add_leak(self, leak, num_threads=4):
        '''
        benchmarks for adding 1M accounts:
            (best average: ~62,500 per second)
                batch size - time
                =================
                100 - 2:03
                1000 - 1:51
                5000 - 1:47
                10000 - 1:36
                100000 - 1:37
                =======================
                10000 (x2 threads) - 1:04
                10000 (x4 threads) - 0:38
                10000 (x8 threads) - 0:35
                early implementation with low-level mp.Process() and mp.Queue(): ?? or was it Pipe() WHO KNOWS
                    10000 (x8 procs, x1 threads) - 0:13
                later implementation with mp.Pool() and mp.manager.Queue():
                    10000 (x8 procs, x1 threads) - 0:23
                    10000 (x4 procs, x2 threads) - 0:21
                    10000 (x2 procs, x4 threads) - 0:24
                later implementation attempting to replicate previous results:
                    10000 (x8 procs, x1 threads) - 0:18
                    10000 (x4 procs, x2 threads) - 0:20
                    10000 (x4 procs, x3 threads) - 0:19
                    10000 (x8 procs, x2 threads) - 0:17
                mp.Process() and mp.Pipe():
                    10000 (x8 procs, x1 threads) - 0:19
                    10000 (x4 procs, x2 threads) - 0:20
                    10000 (x4 procs, x3 threads) - 0:17
                    10000 (x4 procs, x4 threads) - 0:17
                    10000 (x8 procs, x2 threads) - 0:16

        Benchmarks for LinkedIn:
            (average: ~21,600 per second)
                104,957,167 (x8 procs, x2 threads) - 01:20:59
                    Total Accounts: 104,957,167
                    Unique Accounts: 104,957,162 (100.0%)
                    Time Elapsed: 01:20:59

            (average: ~65,400 per second)
                104,957,167 (x24 procs, x2 shards, tmpfs [no storage bottleneck]) - 0:26:46
                    Total Accounts: 104,957,167
                    Unique Accounts: 104,957,162 (100.0%)
                    Time Elapsed: 0 hours, 26 minutes, 46 seconds

        Benchmarks for Exploit.in:
            16 threads (with tmpfs):
                [+] Total Accounts: 684,676,603
                [+] Unique Accounts: 684,676,603 (100.0%)
                [+] Time Elapsed: 7 hours, 21 minutes, 27 seconds
            16 threads (with tmpfs + rsync every 30 minutes)
                [+] Total Accounts: 684,676,603
                [+] Unique Accounts: 649,522,395 (94.9%)
                [+] Time Elapsed: 9 hours, 2 minutes, 28 seconds

        Benchmarks for bigDB:
            11 threads on IBM, mongo + mongo meta (3-2-2019)
                [+] Total Accounts: 2,674,862,578
                [+] Unique Accounts: 1,093,289,423 (40.9%)
                [+] Time Elapsed: 66 hours, 17 minutes, 16 seconds
                (675,470 per minute)

            50 threads on IBM, mongo primary only, 10 shards (5-7-2019)
                [+] Import results for "bigDB/bigDB"
                [+]    total accounts: 2,679,632,050
                [+]    unique accounts: 832,557,894 (31.1%)
                [+]    time elapsed: 51 hours, 27 minutes, 0 second
        '''

        pool = []

        self.log.debug('Adding leak {}'.format(str(leak.source)))
        self.log.debug('Using {} threads'.format(num_threads))

        try:
            self.leak_size = len(leak)
        except TypeError:
            self.leak_size = 0

        start_time = time.time()
        batch_queue = multiprocessing.Queue(num_threads*10)
        result_queue = multiprocessing.Queue(num_threads*10)
        comms_queues = [multiprocessing.Queue(num_threads*10)] * num_threads

        try:

            source_id = self.add_source(leak.source)

            # in my experience, there's no such thing as luck
            p = [None]
            for thread_id in range(num_threads):
                comms_queue = comms_queues[thread_id]
                while 1:
                    p[0] = multiprocessing.Process(target=self._add_batches, args=(batch_queue, result_queue, comms_queue, source_id), daemon=True)
                    sleep(.2)
                    try:
                        p[0].start()
                    except AttributeError:
                        # AttributeError: 'NoneType' object has no attribute 'poll'
                        continue

                    sleep(.5)

                    # Check if thread sent success signal
                    try:
                        signal = comms_queue.get_nowait()
                        if signal == 'huge_success':
                            pool.append(p[0])
                            self.log.debug('Worker started')
                            self.log.debug('Thread {} started successfully'.format(thread_id))
                            break

                    except queue.Empty:
                        pass

                    # Kill thread and try again if it failed to start
                    self.log.debug('Thread {} failed to start, terminating'.format(thread_id))

                    tries = 10
                    while tries > 0:
                        tries -= 1
                        try:
                            p[0].terminate()
                            sleep(.2)
                            p[0].kill()
                            sleep(.2)
                            p[0].close()
                            p.clear()
                            p = [None]
                        except ValueError:
                            # ValueError "Cannot close a process while it is still running."
                            sleep(.1)
                            continue
                        break


            # stuff it down the pipes
            for batch in self._gen_batches(leak, source_id):
                batch_queue.put(batch)

            # send shutdown signal to threads
            for _ in range(num_threads+5):
                batch_queue.put(None)

            # retrieve counters from finished processes
            threads_finished = 0
            while 1:
                try:
                    new_accounts = result_queue.get_nowait()
                    if new_accounts is None:
                        self.log.debug('Worker finished')
                        threads_finished += 1
                        if threads_finished == num_threads:
                            break
                    else:
                        self.leak_unique += new_accounts
                        self.counters.update_one({'collection': 'sources'}, {'$set': {str(source_id): self.leak_overall}}, upsert=True)
                except queue.Empty:
                    #print('threads finished: {}/{}'.format(threads_finished, num_threads))
                    #print('threads alive: ' + str([p.is_alive() for p in pool]))
                    sleep(1)
                    continue

            # empty contents of batch_queue
            while 1:
                try:
                    batch_queue.get_nowait()
                except queue.Empty:
                    break

            # retrieve any errors:
            errors = []
            for comms_queue in comms_queues:
                while 1:
                    try:
                        error = comms_queue.get_nowait()
                        if error not in ('huge_success', 'all_done_here'):
                            errors.append(error)
                    except queue.Empty:
                        break

            end_time = time.time()
            time_elapsed = (end_time - start_time)

            if self.leak_overall > 0:
                self.log.info('{:,}/{:,} ({:.2f}%) unique accounts in "{}".  Time elapsed: {:02d}:{:02d}:{:02d}'.format(
                    self.leak_unique,
                    self.leak_overall,
                    ((self.leak_unique/self.leak_overall)*100), 
                    leak.source.name,
                    int(time_elapsed/3600),
                    int((time_elapsed%3600)/60),
                    int((time_elapsed%3600)%60)))

            if errors:
                self.log.error('Errors:')
                for e in errors:
                    self.log.error('       {}'.format(str(e)))

        except pymongo.errors.PyMongoError as e:
            error = str(e)
            try:
                error += (str(e.details))
            except AttributeError:
                pass
            self.log.error(error)

        except QuickParseError as e:
            self.log.error(str(e))

        except Exception as e:
            self.log.critical(str(traceback.format_exc()))

        finally:
            # reset leak counters
            self.leak_unique = 0
            self.leak_overall = 0
            self.leak_size = 0
            # let the bodies hit the floor
            for p in pool:
                tries = 10
                while tries > 0:
                    tries -= 1
                    try:
                        p.terminate()
                        sleep(.1)
                        p.kill()
                        sleep(.1)
                        p.close()
                    except ValueError:
                        # ValueError "Cannot close a process while it is still running."
                        sleep(.1)
                        continue
                    break


    def delete_leak(self, source_id, batch_size=10000):

        if not self.use_metadata:
            raise CredShedMetadataError('Removing leaks requires access to metadata. No metadata database is currently attached.')

        else:
            source = self.get_source(source_id)
            accounts_deleted = 0
            to_delete = []

            self.log.info('\nDeleting leak "{}{}"'.format(source.name, ':{}'.format(source.hashtype) if source.hashtype else ''))

            try:

                # delete accounts
                for result in self.account_tags.find({'s': [source_id]}, {'_id': 1}):
                    to_delete.append(pymongo.DeleteOne(result))
                    if len(to_delete) % batch_size == 0:
                        accounts_deleted += self.accounts.bulk_write(to_delete, ordered=False).deleted_count
                        to_delete.clear()
                        errprint('\rDeleted {:,} accounts'.format(accounts_deleted), end='')

                if to_delete:
                    accounts_deleted += self.accounts.bulk_write(to_delete, ordered=False).deleted_count

                # delete out of tags collection
                self.account_tags.delete_many({'s': [source_id]})
                # pull source ID from affected accounts
                self.account_tags.update_many({'s': source_id}, {'$pull': {'s': source_id}})

                errprint('\r[+] Deleted {:,} accounts'.format(accounts_deleted), end='')

                self.sources.delete_many({'_id': source_id})
                self.counters.update_one({'collection': 'sources'}, {'$unset': {str(source_id): ''}})


            except TypeError as e:
                self.log.error(str(e))
                self.log.error('[!] Can\'t find source "{}:{}"'.format(source.name, source.hashtype))

            errprint('')
            self.log.info('{:,} accounts deleted'.format(accounts_deleted))

            return accounts_deleted


    def add_source(self, source):

        source_doc = source.document(misc=False, date=False)

        source_in_db = self.sources.find_one(source_doc)
        if source_in_db is not None:
            source_id, source_name = source_in_db['_id'], source_in_db['name']
            self.log.info('Source ID {} ({}) already exists, merging'.format(source_id, source_name))
            return source_id
            #assert False, 'Source already exists'
        else:
            d = self.counters.find_one({'collection': 'sources'})
            id_counter = (d['id_counter'] if d else 0)

            source_doc = source.document(misc=True, date=True)
            while 1:       

                try:
                    id_counter += 1
                    source_doc['_id'] = id_counter
                    self.sources.insert_one(source_doc)
                    break
                except pymongo.errors.DuplicateKeyError:
                    continue

            self.counters.update_one({'collection': 'sources'}, {'$set': {'id_counter': id_counter}}, upsert=True)

        return id_counter


    def stats(self, accounts=False, counters=False, sources=True, db=False):
        '''
        prints database statistics
        returns most recently added source ID, if applicable
        '''

        most_recent_source_id = 0
        stats = []

        try:

            if accounts:
                accounts_stats = self.main_db.command('collstats', 'accounts', scale=1048576)
                stats.append('[+] Account Stats (MB):')
                for k in accounts_stats:
                    if k not in ['wiredTiger', 'indexDetails', 'shards', 'raw']:
                        stats.append('\t{}: {}'.format(k, accounts_stats[k]))
            stats.append('')

            '''
            if counters:
                counters_stats = self.db.command('collstats', 'counters', scale=1048576)
                self.log.info('[+] Counter Stats (MB):')
                for k in counters_stats:
                    if k not in ['wiredTiger', 'indexDetails']:
                        self.log.info('\t{}: {}'.format(k, counters_stats[k]))
                self.log.info()
            '''

            if sources:

                sources_stats = dict()

                for s in self.sources.find({}):
                    sources_stats[s['_id']] = Source(s['name'], s['hashtype'], s['misc'])

                if sources_stats:
                    stats.append('[+] Leaks in DB:')
                    for _id in sources_stats:
                        source = sources_stats[_id]
                        try:
                            source_size = ' [{:,}]'.format(self.counters.find_one({'collection': 'sources'})[str(_id)])
                        except KeyError:
                            source_size = ''

                        stats.append('\t{}: {}{}'.format(_id, str(source), source_size))
                    stats.append('')

        except pymongo.errors.OperationFailure:
            stats.append('[!] No accounts added yet\n')

        if db:
            db_stats = self.main_db.command('dbstats', scale=1048576)
            stats.append('[+] DB Stats (MB):')
            for k in db_stats:
                if k not in ['raw']:
                    stats.append('\t{}: {}'.format(k, db_stats[k]))

        return '\n'.join(stats)



    def most_recent_source_id(self):
        '''
        returns source with highest ID
        or None if there are no leaks loaded
        '''

        source_ids = [s['_id'] for s in list(self.sources.find({}, {'_id': True}))]
        if source_ids:
            source_ids.sort()
            return source_ids[-1]
        else:
            return None



    def account_count(self):

        try:
            collstats = self.main_db.command('collstats', 'accounts', scale=1048576)
            num_accounts_in_db = collstats['count']
        except KeyError:
            num_accounts_in_db = 0
        except pymongo.PyMongoError as e:
            error = str(e)
            try:
                error += (str(e.details))
            except AttributeError:
                pass
            raise CredShedDatabaseError(error)

        return int(num_accounts_in_db)


    def get_source(self, _id):

        try:
            s = self.sources.find_one({'_id': int(_id)})
            try:
                return Source(s['name'], s['hashtype'], s['misc'])
            except (TypeError, KeyError):
                return None

        except pymongo.PyMongoError as e:
            error = str(e)
            try:
                error += (str(e.details))
            except AttributeError:
                pass
            raise CredShedDatabaseError(error)


    def parse_config(self):

        # parse config file
        config_filename = Path(__file__).resolve().parent.parent / 'credshed.config'
        if not config_filename.is_file():
            raise CredShedConfigError('Unable to find credshed config at {}'.format(config_filename))

        config = configparser.ConfigParser()
        config.read(str(config_filename))

        return config



    def close(self):

        try:
            self.main_client.close()
            self.meta_client.close()
        except AttributeError:
            pass


    def _gen_batches(self, leak, source_id, batch_size=20000):

        batch = []
        for account in leak:
            account_doc = account.document

            if account_doc is not None:
                batch.append(account_doc)
                self.leak_overall += 1

            if batch and ((self.leak_overall) % batch_size == 0):
                yield batch
                batch = []
            
        if batch:
            yield batch


    def _add_batches(self, batch_queue, result_queue, comms_queue, source_id):

        try:

            max_attempts = 3
            unique_accounts = 0

            if not self.metadata_only:
                main_server = self.config['MONGO PRIMARY']['server']
                main_port = int(self.config['MONGO PRIMARY']['port'])
                main_db = self.config['MONGO PRIMARY']['db']

                mongo_main_client = pymongo.MongoClient(main_server, main_port, username=self.mongo_user, password=self.mongo_pass)
                mongo_main = mongo_main_client[main_db]

            if self.use_metadata:
                meta_server = self.config['MONGO METADATA']['server']
                meta_port = int(self.config['MONGO METADATA']['port'])
                meta_db = self.config['MONGO METADATA']['db']
                mongo_meta_client = pymongo.MongoClient(meta_server, meta_port, username=self.mongo_user, password=self.mongo_pass)
                mongo_meta = mongo_meta_client[meta_db]

            try:
                comms_queue.put('huge_success')
                sleep(1)

                while 1:
                    try:
                        #self.log.info('[+] Getting batch')
                        num_inserted = 0
                        batch = batch_queue.get_nowait()

                        if batch is None:
                            break
                        else:
                            '''
                            timeout_value = (int(len(batch) / 500)) + (5 * max_attempts) + 1
                            try:
                                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as thread_executor:

                                    main_thread = thread_executor.submit(self._mongo_main_add_batch, mongo_main, source_id, copy.deepcopy(batch))
                                    meta_thread = thread_executor.submit(self._mongo_meta_add_batch, mongo_meta, source_id, batch)

                                num_inserted = main_thread.result(timeout=timeout_value)

                            except concurrent.futures.TimeoutError:
                                #comms_queue.put('"main" mongodb thread timed out after {:,} seconds'.format(timeout_value))
                                continue

                            finally:
                                unique_accounts += num_inserted
                            '''

                            try:

                                if not self.metadata_only:
                                    num_inserted = self._mongo_main_add_batch(mongo_main, source_id, copy.deepcopy(batch), comms_queue)
                                if self.use_metadata:
                                    _ = self._mongo_meta_add_batch(mongo_meta, source_id, batch, comms_queue)
                                    if self.metadata_only:
                                        num_inserted = int(_)

                            except pymongo.errors.PyMongoError as e:
                                error = str(e)
                                try:
                                    error += (str(e.details))
                                except AttributeError:
                                    pass
                                comms_queue.put('Error in _add_batches():\n{}'.format(error))

                            unique_accounts += num_inserted

                    except queue.Empty:
                        sleep(.1)
                        continue

            except KeyboardInterrupt:
                return

            except Exception as e:
                comms_queue.put('Error in _add_batches():\n{}'.format(str(traceback.format_exc())))
                return

            finally:
                try:
                    #mongo_main_client.close()
                    #mongo_meta_client.close()
                    result_queue.put(unique_accounts)
                    # send signal that thread is finished
                    result_queue.put(None)
                except:
                    pass

        except KeyboardInterrupt:
            return



    @staticmethod
    def _mongo_main_add_batch(_mongo, source_id, batch, comms_queue, max_attempts=3):

        unique_accounts = 0
        attempts_left = int(max_attempts)
        mongo_batch = []
        error_details = ''

        for account_doc in batch:
            _id = account_doc.pop('_id')
            mongo_batch.append(pymongo.UpdateOne({'_id': _id}, {'$setOnInsert': account_doc}, upsert=True))

        while attempts_left > 0:
            try:

                result = _mongo.accounts.bulk_write(mongo_batch, ordered=False)
                unique_accounts = result.upserted_count
                return unique_accounts

            # sleep for a bit and try again if there's an error
            except (pymongo.errors.OperationFailure, pymongo.errors.InvalidOperation) as e:
                error = '\nError adding account batch to main DB.  Attempting to continue.\n{}'.format(str(e)[:64])
                try:
                    error += ('\n' + str(e.details)[:64])
                except AttributeError:
                    pass
                comms_queue.put(error)
                attempts_left -= 1
                sleep(5)
                continue

        raise CredShedDatabaseError('Failed to add batch to main DB after {} tries'.format(max_attempts))



    @staticmethod
    def _mongo_meta_add_batch(_mongo, source_id, batch, comms_queue, max_attempts=3):

        attempts_left = int(max_attempts)
        mongo_tags_batch = []

        for account_doc in batch:
            _id = account_doc['_id']
            mongo_tags_batch.append(pymongo.UpdateOne({'_id': _id}, {'$addToSet': {'s': source_id}}, upsert=True))

        while attempts_left > 0:
            try:

                _mongo.account_tags.bulk_write(mongo_tags_batch, ordered=False)
                return

            # sleep for a bit and try again if there's an error
            except (pymongo.errors.OperationFailure, pymongo.errors.InvalidOperation) as e:
                error = '\nError adding account batch to meta DB.  Attempting to continue.\n{}'.format(str(e)[:64])
                try:
                    error += ('\n' + str(e.details)[:64])
                except AttributeError:
                    pass
                comms_queue.put(error)
                attempts_left -= 1
                sleep(5)
                continue

        raise CredShedDatabaseError('\nFailed to add batch to meta DB after {} tries'.format(max_attempts))