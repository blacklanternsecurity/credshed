#!/usr/bin/env python3.7

import copy
import time
import queue
import redis
import pymongo
from .leak import *
import elasticsearch
from time import sleep
import multiprocessing
from hashlib import sha1
from pathlib import Path
import concurrent.futures
from subprocess import run, PIPE
from elasticsearch import helpers


class DB():

    def __init__(self):

        ### ELASTIC ###
        self.es        = elasticsearch.Elasticsearch()
        self.es_index  = elasticsearch.client.IndicesClient(self.es)

        # create indexes (basically tables)
        if not self.es.indices.exists('accounts'):
            # 1M accounts:
            #  - default compression:
            #    - 48M file --> 317M db
            #  - best_compression:
            #    - 48M file -- > 299M db
            self.es.indices.create('accounts', body={'codec': 'best_compression'})
        if not self.es.indices.exists('sources'):
            self.es.indices.create('sources')
        if not self.es.indices.exists('counters'):
            self.es.indices.create('counters')


        # set up mappings
        mappings = {
            'properties':
            {
                'username': {
                    'type': 'keyword',
                    'ignore_above': 128
                },
                'email': {
                    'type': 'keyword',
                    'ignore_above': 128
                },
                'domain': {
                    'type': 'keyword',
                    'ignore_above': 128
                },
                'password': {
                    'type': 'keyword',
                    'ignore_above': 128,
                    'index': False
                },
                'misc': {
                    'type': 'text',
                    'index': False,
                    'norms': False,
                    'index_options': 'freqs'
                }
            }
        }
        '''
                'password': {
                    'type': 'text',
                    'index': False,
                    'norms': False,
                    'index_options': 'freqs'
                }

        '''
        try:
            self.es_index.put_mapping(index='accounts', doc_type='account', body=mappings)
        except elasticsearch.exceptions.RequestError:
            errprint('[!] Error setting Elasticsearch mappings')


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

            



    def add_leak(self, leak, num_threads=4, chunk_size=5000):
        '''
        benchmarks for adding 1M accounts:
            ELASTIC:
                streaming_bulk:
                    chunk size - time
                    =================
                    500     0:43
                    1000    0:43
                    5000    0:38
                    10000   0:37
                    20000   0:37
                    =================

            MONGO:
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
            errprint('     - {} threads'.format(num_threads))
            errprint('     - chunk size: {}'.format(chunk_size))

            try:
                self.leak_size = len(leak)
            except TypeError:
                self.leak_size = 0

            start_time = time.time()

            # temporarily disable index refresh and replication for performance
            self.es_index.put_settings(index='accounts', body={'index': {'refresh_interval': -1}})
            self.es_index.put_settings(index='accounts', body={'index': {'number_of_replicas': 0}})

            bulk_stream = self._bulk_account_generator(leak)
            # for success, result in helpers.parallel_bulk(client=self.es, actions=bulk_stream, thread_count=num_threads, chunk_size=chunk_size):
            for success, result in helpers.streaming_bulk(client=self.es, actions=bulk_stream, chunk_size=chunk_size):
                self.leak_overall += 1
                if success:
                    if result:
                        if result['index']['result'] == 'created':
                            self.leak_unique += 1
                if self.leak_overall % chunk_size == 0:
                    errprint('\r[+] {:,}{}  '.format(self.leak_overall, (' ({:.3f})%'.format(self.leak_overall / self.leak_size * 100) if self.leak_size else '')), end='')


            end_time = time.time()
            time_elapsed = (end_time - start_time)

            if self.leak_overall > 0:
                errprint('\n[+] Total Accounts: {:,}'.format(self.leak_overall))
                errprint('[+] Unique Accounts: {:,} ({:.1f}%)'.format(self.leak_unique, ((self.leak_unique/self.leak_overall)*100)))
                errprint('[+] Time Elapsed: {} hours, {} minutes, {} seconds\n'.format(int(time_elapsed/3600), int((time_elapsed%3600)/60), int((time_elapsed%3600)%60)))

        except KeyboardInterrupt:
            errprint('[!] Import stopped')
            raise KeyboardInterrupt

        finally:
            # reset leak counters
            self.leak_unique = 0
            self.leak_overall = 0
            self.leak_size = 0

            # reset elasticsearch settings
            self.es_index.put_settings(index='accounts', body={'index': {'refresh_interval': '1s'}})
            self.es_index.put_settings(index='accounts', body={'index': {'number_of_replicas': 1}})


    def remove_leak(self, source_id, batch_size=10000):

        source = self.get_source(source_id)
        accounts_deleted = 0
        to_delete = []

        errprint('[*] Deleting leak "{}{}"'.format(source.name, ':{}'.format(source.hashtype) if source.hashtype else ''))

        try:

            '''
            #source_id = self.sources.find_one(source.document())['_id']
            source_bytes = source_id.to_bytes(5, 'big')
            for _id in self.redis.scan_iter('a:*'):
                self.redis.lrem(_id, 0, source_bytes)
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
            '''

            #accounts_deleted = self.accounts.delete_many({'sources': [source_id]}).deleted_count
            # self.accounts.update_many({'sources': {'$in': [source_id]}}, {'$pull': {'sources': source_id}})
            self.sources.delete_one(source.document())
            self.counters.update_one({'collection': 'sources'}, {'$unset': {str(source_id): ''}})

        except TypeError as e:
            errprint(str(e))
            errprint('[!] Can\'t find source "{}:{}"'.format(source.name, source.hashtype))

        errprint('[*] {:,} accounts deleted'.format(accounts_deleted))
        errprint('[*] Done')
        return accounts_deleted


    def add_source(self, source):

        source_doc = source.document()
        source_id = 1

        # check if source already exists
        source_match = self._elastic_exact_match(source_doc, index='sources', doc_type='source')
        if source_match:
            print(str(source_match))
            assert False, 'Source already exists'
        else:
            # source id = the number of sources in the index + 1
            source_id = self.es.count(index='sources')['count'] + 1

            # loop until there's a unique one
            while 1:
                try:
                    self.es.create(index='sources', doc_type='source', id=source_id, body=source_doc)
                    break

                except elasticsearch.exceptions.ConflictError:
                    source_id += 1
                    continue

        return source_id


    def show_stats(self, accounts=False, counters=False, sources=True, db=False):
        '''
        prints database statistics
        returns most recently added source ID, if applicable
        '''

        most_recent_source_id = 0

        try:

            if accounts:
                accounts_stats = self.db.command('collstats', 'accounts', scale=1048576)
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
            db_stats = self.db.command('dbstats', scale=1048576)
            errprint('[+] DB Stats (MB):')
            for k in db_stats:
                errprint('\t{}: {}'.format(k, db_stats[k]))

        return most_recent_source_id


    def get_source(self, _id):

        s = self.sources.find_one({'_id': int(_id)})
        try:
            return Source(s['name'], s['hashtype'], s['misc'])
        except (TypeError, KeyError):
            return None



    def _bulk_account_generator(self, leak):

        for account in leak:
            account_id = account.to_object_id()
            account_doc = account.document()

            yield {'_index': 'accounts', '_type': 'account', '_id': account_id, '_source': account_doc}



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
        _mongo = pymongo.MongoClient()['dump']
        unique_accounts = 0

        for batch in iter(batch_queue.get, None):

            with concurrent.futures.ThreadPoolExecutor() as thread_executor:

                mthread = thread_executor.submit(self._mongo_add_batch, _mongo, source_id, copy.deepcopy(batch))
                #rthread = thread_executor.submit(self._redis_add_batch, _redis, source_id, batch)

                thread_executor.shutdown(wait=True)
                unique_accounts += mthread.result()


        result_queue.put(unique_accounts)
        errprint('[+] Worker finished')



    def _elastic_exact_match(self, doc, index='accounts', doc_type='account'):

        # construct query object
        query_obj = {'query': {'bool': {'must': []}}}
        for key, value in doc.items():
            if value:
                query_obj['query']['bool']['must'].append({'match': {key: value}})

        return self.es.search(index=index, doc_type=doc_type, body=query_obj)['hits']['hits']


    @staticmethod
    def _redis_add_batch(_redis, source_id, batch):

        for account_doc in batch:
            _redis.lpush('a:' + account_doc['_id'], source_id.to_bytes(5, 'big'))


    @staticmethod
    def _mongo_add_batch(_mongo, source_id, batch, max_attempts=3):

        unique_accounts = 0
        attempts_left = int(max_attempts)
        mongo_batch = []

        for account_doc in batch:
            _id = account_doc.pop('_id')
            mongo_batch.append(pymongo.UpdateOne({'_id': _id}, {'$setOnInsert': account_doc}, upsert=True))

        while attempts_left > 0:
            try:

                result = _mongo.accounts.bulk_write(mongo_batch, ordered=False)
                _mongo.counters.update_one({'collection': 'sources'}, {'$inc': {str(source_id): len(mongo_batch)}}, upsert=True)
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
                sleep(1)
                continue

        errprint('\n[!] Failed to add batch after {} tries'.format(max_attempts))
        return unique_accounts