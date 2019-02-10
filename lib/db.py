#!/usr/bin/env python3.7
'''

try and fix background/foreground issue

    Traceback (most recent call last):
      File "/usr/lib/python3.7/multiprocessing/process.py", line 297, in _bootstrap
        self.run()
      File "/usr/lib/python3.7/multiprocessing/process.py", line 99, in run
        self._target(*self._args, **self._kwargs)
      File "/mnt/s1/leak/bin/lib/db.py", line 389, in _add_batches
        unique_accounts += mthread.result()
      File "/usr/lib/python3.7/concurrent/futures/_base.py", line 425, in result
        return self.__get_result()
      File "/usr/lib/python3.7/concurrent/futures/_base.py", line 384, in __get_result
        raise self._exception
      File "/usr/lib/python3.7/concurrent/futures/thread.py", line 57, in run
        result = self.fn(*self.args, **self.kwargs)
      File "/mnt/s1/leak/bin/lib/db.py", line 419, in _mongo_add_batch
        _mongo.counters.update_one({'collection': 'sources'}, {'$inc': {str(source_id): len(mongo_batch)}}, upsert=True)
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/collection.py", line 995, in update_one
        session=session),
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/collection.py", line 851, in _update_retryable
        _update, session)
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/mongo_client.py", line 1248, in _retryable_write
        return self._retry_with_session(retryable, func, s, None)
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/mongo_client.py", line 1201, in _retry_with_session
        return func(session, sock_info, retryable)
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/collection.py", line 847, in _update
        retryable_write=retryable_write)
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/collection.py", line 817, in _update
        retryable_write=retryable_write).copy()
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/pool.py", line 584, in command
        self._raise_connection_failure(error)
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/pool.py", line 743, in _raise_connection_failure
        _raise_connection_failure(self.address, error)
      File "/home/user/.local/lib/python3.7/site-packages/pymongo/pool.py", line 283, in _raise_connection_failure
        raise AutoReconnect(msg)
    pymongo.errors.AutoReconnect: localhost:27017: [Errno 32] Broken pipe
'''

import copy
import time
import queue
import redis
import pymongo
from .leak import *
from time import sleep
import multiprocessing
from hashlib import sha1
from pathlib import Path
import concurrent.futures
from subprocess import run, PIPE


class DB():

    def __init__(self):

        ### MONGO ###
        self.shard_client = pymongo.MongoClient('127.0.0.1', 27017)
        self.noshard_client = pymongo.MongoClient('127.0.0.1', 27019)
        # databases
        self.shard_db = self.shard_client['credshed']
        self.noshard_db = self.noshard_client['credshed']
        # accounts
        self.accounts = self.shard_db.accounts

        #self.accounts.create_index([('id', pymongo.ASCENDING)])
        #self.accounts.create_index([('username', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('domain', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('password', pymongo.ASCENDING), ('username', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('email', pymongo.ASCENDING), ('password', pymongo.ASCENDING)], sparse=True, background=True)

        # "warm up" the indexes (load them into memory)
        # roughly equivalent to the "touch" db command in mmap
        # https://grokbase.com/t/gg/mongodb-user/154qhs7402/warming-up-index-data-is-wiredtiger
        # index_char_range = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9']
        # self.accounts.find({'email': {'$in': index_char_range }, 'password': {'$in': index_char_range } }).count()
        # self.accounts.find({'domain': {'$in': index_char_range } }).count()
        # self.accounts.find({'password': {'$in': index_char_range }, 'username': {'$in': index_char_range } }).count()
        # self.accounts.find({'username': {'$in': index_char_range } }).count()
        # self.db.command('touch', 'accounts', index=True)
        # sources
        self.sources = self.noshard_db.sources
        # counters
        self.counters = self.noshard_db.counters

        ### REDIS ###
        self.redis = redis.StrictRedis()

        # leak-specific counters
        self.leak_unique = 0
        self.leak_overall = 0
        self.leak_size = 0


    def find(self, keywords, password=False, misc=False):
        '''
        ~ 2 minutes to regex-search 100M-entry DB
        '''

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


            try:
                email, domain = keyword.lower().split('@')[:2]
                domain_keyword = base64.b64encode(sha1(b'.'.join(domain.lower().encode().split(b'.')[-2:])).digest()).decode()[:6]
                domain_regex = r'^{}.*'.format(domain_keyword).replace('+', r'\+')
                errprint('[+] Searching by full email')
                query = {'$and': [{'email': email}, {'_id': {'$regex': domain_regex}}]}
                #errprint(query)
                results['emails'] = self.accounts.find(query)
                #results['emails'] = self.accounts.find({'email': email, '_id': {'$regex': domain_regex}})
                #results['emails'] = self.accounts.find({'email': email})
            except ValueError:
                domain = keyword.lower()
                domain_keyword = base64.b64encode(sha1(b'.'.join(keyword.lower().encode().split(b'.')[-2:])).digest()).decode()[:6]
                domain_regex = r'^{}.*'.format(domain_keyword).replace('+', r'\+')
                errprint('[+] Searching by domain')
                query = {'_id': {'$regex': domain_regex}}
                #errprint(query)
                results['emails'] = self.accounts.find(query)

            for category in results:
                for result in results[category]:
                    yield Account.from_document(result)

            



    def add_leak(self, leak, num_threads=2):
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
        '''

        try:

            errprint('[+] Adding leak')
            errprint('[+] Using {} threads'.format(num_threads))

            try:
                self.leak_size = len(leak)
            except TypeError:
                self.leak_size = 0

            source_id = self.add_source(leak.source)
            start_time = time.time()
            batch_queue = multiprocessing.Queue(num_threads*2)
            result_queue = multiprocessing.Queue(num_threads)

            pool = []
            #pipes = []
            for i in range(num_threads):
                #receiver, sender = multiprocessing.Pipe(duplex=False)
                # errprint('starting process #{}'.format(i))
                p = multiprocessing.Process(target=self._add_batches, args=(batch_queue, result_queue, source_id))
                pool.append(p)
                p.start()
                #pipes.append(sender)

            #i = 0
            for batch in self._gen_batches(leak, source_id):
                #pipes[i%num_threads].send(batch)
                batch_queue.put(batch)
                errprint('\r[+] {:,}{}  '.format(self.leak_overall, (' ({:.3f})%'.format(self.leak_overall / self.leak_size * 100) if self.leak_size else '')), end='')
                #i += 1
            errprint()

            # sending shutdown signal to threads
            for q in range(num_threads+1):
                batch_queue.put(None)

            for p in pool:
                p.join()
            
            # retrieve counters from finished processes
            while 1:
                try:
                    self.leak_unique += result_queue.get_nowait()
                except queue.Empty:
                    break

            end_time = time.time()
            time_elapsed = (end_time - start_time)

            if self.leak_overall > 0:
                errprint('\n[+] Total Accounts: {:,}'.format(self.leak_overall))
                errprint('[+] Unique Accounts: {:,} ({:.1f}%)'.format(self.leak_unique, ((self.leak_unique/self.leak_overall)*100)))
                errprint('[+] Time Elapsed: {} hours, {} minutes, {} seconds\n'.format(int(time_elapsed/3600), int((time_elapsed%3600)/60), int((time_elapsed%3600)%60)))

        except KeyboardInterrupt:
            [p.terminate() for p in pool]
            raise KeyboardInterrupt
        finally:
            # reset leak counters
            self.leak_unique = 0
            self.leak_overall = 0
            self.leak_size = 0


    def remove_leak(self, source_id, batch_size=10000):

        source = self.get_source(source_id)
        accounts_deleted = 0
        to_delete = []

        errprint('[*] Deleting leak "{}{}"'.format(source.name, ':{}'.format(source.hashtype) if source.hashtype else ''))

        try:

            # source_bytes = source_id.to_bytes(4, 'big')
            for _id in self.redis.scan_iter('a:*'):
                self.redis.lrem(_id, 0, source_id)
                if not self.redis.exists(_id):
                    to_delete.append(pymongo.DeleteOne({'_id': _id[2:].decode()}))
                    #to_delete.append(_id[2:].decode())
                    accounts_deleted += 1

                if to_delete and accounts_deleted % batch_size == 0:
                    #self.accounts.remove({'_id': {'$in': [d for d in to_delete]}})
                    self.accounts.bulk_write([d for d in to_delete])
                    to_delete.clear()

            if to_delete:
                #self.accounts.remove({'_id': {'$in': [d for d in to_delete]}})
                self.accounts.bulk_write([d for d in to_delete])


            #accounts_deleted = self.accounts.delete_many({'sources': [source_id]}).deleted_count
            # self.accounts.update_many({'sources': {'$in': [source_id]}}, {'$pull': {'sources': source_id}})
            self.sources.delete_one({'_id': source_id})
            self.counters.update_one({'collection': 'sources'}, {'$unset': {str(source_id): ''}})

        except TypeError as e:
            errprint(str(e))
            errprint('[!] Can\'t find source "{}:{}"'.format(source.name, source.hashtype))

        errprint('[*] {:,} accounts deleted'.format(accounts_deleted))
        errprint('[*] Done')
        return accounts_deleted


    def add_source(self, source):

        source_doc = source.document(misc=False, date=False)

        if self.sources.find_one(source_doc) is not None:
            assert False, 'Source already exists'
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


    def show_stats(self, accounts=False, counters=False, sources=True, db=False):
        '''
        prints database statistics
        returns most recently added source ID, if applicable
        '''

        most_recent_source_id = 0

        try:

            if accounts:
                accounts_stats = self.shard_db.command('collstats', 'accounts', scale=1048576)
                errprint('[+] Account Stats (MB):')
                for k in accounts_stats:
                    if k not in ['wiredTiger', 'indexDetails']:
                        errprint('\t{}: {}'.format(k, accounts_stats[k]))
            errprint()

            '''
            if counters:
                counters_stats = self.db.command('collstats', 'counters', scale=1048576)
                errprint('[+] Counter Stats (MB):')
                for k in counters_stats:
                    if k not in ['wiredTiger', 'indexDetails']:
                        errprint('\t{}: {}'.format(k, counters_stats[k]))
                errprint()
            '''

            if sources:

                sources_stats = dict()

                for s in self.sources.find({}):
                    sources_stats[s['_id']] = Source(s['name'], s['hashtype'], s['misc'])

                if sources_stats:
                    errprint('[+] Leaks in DB:')
                    for _id in sources_stats:
                        source = sources_stats[_id]
                        try:
                            source_size = ' [{:,}]'.format(self.counters.find_one({'collection': 'sources'})[str(_id)])
                        except KeyError:
                            source_size = ''
                        most_recent_source_id = _id

                        errprint('\t{}: {}{}'.format(_id, str(source), source_size))
                    errprint()

        except pymongo.errors.OperationFailure:
            errprint('[!] No accounts added yet', end='\n\n')

        if db:
            db_stats = self.shard_db.command('dbstats', scale=1048576)
            errprint('[+] DB Stats (MB):')
            for k in db_stats:
                errprint('\t{}: {}'.format(k, db_stats[k]))

        return most_recent_source_id


    def get_source(self, _id):

        s = self.sources.find_one({'_id': int(_id)})
        try:
            return Source(s['name'], s['hashtype'], s['misc'], s['date'])
        except (TypeError, KeyError):
            return None


    def _gen_batches(self, leak, source_id, batch_size=10000):

        batch = []
        for account in leak:
            account_doc = account.document()

            if account_doc is not None:
                batch.append(account_doc)
                self.leak_overall += 1

            if batch and (self.leak_overall) % batch_size == 0:
                #errprint('BATCH SIZE: {}'.format(len(batch)))
                yield batch
                batch = []
            
        if batch:
            yield batch


    def _add_batches(self, batch_queue, result_queue, source_id):
        '''
        1. upsert and get ObjectID:

            results = self.accounts.find(account.document(), {'_id': 1}, upsert=True)
            for result in results:
                object_id = result['_id'].binary

        2. append source to ObjectID in redis
            - set ?

        '''

        errprint('[+] Worker started')

        _redis = redis.StrictRedis()
        _mongo_shard = pymongo.MongoClient('127.0.0.1', 27017)['credshed']
        _mongo_noshard = pymongo.MongoClient('127.0.0.1', 27019)['credshed']
        unique_accounts = 0

        for batch in iter(batch_queue.get, None):

            with concurrent.futures.ThreadPoolExecutor() as thread_executor:

                mthread = thread_executor.submit(self._mongo_add_batch, _mongo_shard, _mongo_noshard, source_id, copy.deepcopy(batch))
                rthread = thread_executor.submit(self._redis_add_batch, _redis, source_id, batch)

                thread_executor.shutdown(wait=True)
                unique_accounts += mthread.result()


        result_queue.put(unique_accounts)
        errprint('[+] Worker finished')



    @staticmethod
    def _redis_add_batch(_redis, source_id, batch):

        for account_doc in batch:
            _redis.lpush('a:' + account_doc['_id'], source_id)


    @staticmethod
    def _mongo_add_batch(_mongo_shard, _mongo_noshard, source_id, batch, max_attempts=3):

        unique_accounts = 0
        attempts_left = int(max_attempts)
        mongo_batch = []

        for account_doc in batch:
            _id = account_doc.pop('_id')
            # if "sources" array is stored in the document:
            #  db.accounts.update(account_doc, {'$addToSet': {'sources': source_id}}, upsert=True)
            mongo_batch.append(pymongo.UpdateOne({'_id': _id}, {'$setOnInsert': account_doc}, upsert=True))

        while attempts_left > 0:
            try:

                result = _mongo_shard.accounts.bulk_write(mongo_batch, ordered=False)
                _mongo_noshard.counters.update_one({'collection': 'sources'}, {'$inc': {str(source_id): len(mongo_batch)}}, upsert=True)
                unique_accounts = result.upserted_count
                return unique_accounts

            # sleep for a bit and try again if there's an error
            except (pymongo.errors.OperationFailure, pymongo.errors.InvalidOperation) as e:
                errprint('\n[!] Error adding account batch.  Attempting to continue.\n{}'.format(str(e)))
                try:
                    errprint(e.details)
                except:
                    pass
                attempts_left -= 1
                sleep(5)
                continue

        errprint('\n[!] Failed to add batch after {} tries'.format(max_attempts))
        return unique_accounts