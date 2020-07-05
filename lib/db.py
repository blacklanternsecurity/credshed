#!/usr/bin/env python3

# by TheTechromancer

import re
import logging
from .util import *
from . import logger
from .errors import *
from .source import *
from .account import *
from . import validation
from .config import config
from datetime import datetime
from multiprocessing import Manager

import elasticsearch
from elasticsearch import helpers


# set up logging
log = logging.getLogger('credshed.db')


source_lock = Manager().Semaphore()


class DB():

    account_mappings = {
        'properties': {
            # username
            'u': {
                'type': 'keyword',
                'ignore_above': Account.max_length_1,
                'index': False,
                'norms': False,
            },
            # email (left of "@" only, domain is in "_id" field)
            'e': {
                'type': 'keyword',
                'ignore_above': Account.max_length_1,
                'index': True,
                'norms': False,
            },
            # domain (stored reversed for better searching)
            'd': {
                'type': 'keyword',
                'ignore_above': Account.max_length_1,
                'index': True,
                'norms': False
            },
            # password
            'p': {
                'type': 'keyword',
                'ignore_above': Account.max_length_1,
                'index': False,
                'norms': False,
            },
            # hashes (array)
            'h': {
                'type': 'keyword',
                'ignore_above': Account.max_length_2,
                'index': False,
                'norms': False,
            },
            # misc / description
            'm': {
                'type': 'text',
                'index': False,
                'norms': False,
            },
            # sources (array of source IDs)
            's': {
                'type': 'long',
                'index': False,
            }
        }
    }

    source_mappings = {
        'properties': {
            'top_domains': {
                'type': 'flattened',
            },
            'top_misc_basewords': {
                'type': 'flattened',
            },
            'top_password_basewords': {
                'type': 'flattened',
            },
        }
    }

    elastic_scripts = [
        # AddToSet() (account.s)
        {
            'id': 'a',
            'script': {
                'source': 'if ( ! ctx._source.s.contains(params.s) ) { ctx._source.s.add(params.s) }',
                'lang': 'painless',
            }
        },
        # Update Source Filenames
        {
            'id': 'UpdateSourceFilenames',
            'script': {
                'source': 'if ( ! ctx._source.files.contains(params.filename) ) { ctx._source.files.add(params.filename) }',
                'lang': 'painless',
            },
        },
        # Update Source Counters
        {
            'id': 'UpdateSourceCounters',
            'script': {
                'source': 'if ( ctx._source.total_accounts < params.total_accounts ) { ctx._source.total_accounts = params.total_accounts }',
                'lang': 'painless',
            }
        }
    ]


    def __init__(self):

        self._elastic = None
        self._index = None



    @property
    def elastic(self):

        if self._elastic is None:

            self._elastic = elasticsearch.Elasticsearch(
                timeout=30,
                max_retries=10,
                retry_on_timeout=True,
                http_auth=(
                    config['CREDSHED']['username'],
                    config['CREDSHED']['password']
                )
            )

            # create indexes (similar to tables)
            try:
                self._op(
                    self.elastic.indices.create, 
                    'accounts',
                    {
                        'settings' : {
                            'index' : {
                                'number_of_shards': int(config['CREDSHED']['shards'])
                            }
                        }
                    }
                )
            except elasticsearch.exceptions.ElasticsearchException as e:
                log.debug(str(e))

            try:
                self._op(self.elastic.indices.create, 'sources')
            except elasticsearch.exceptions.ElasticsearchException as e:
                log.debug(str(e))


            # set up account mappings
            try:
                self._op(self.index.put_mapping, index='accounts', body=self.account_mappings)
            except elasticsearch.exceptions.RequestError as e:
                log.error('Error setting Elasticsearch account mappings')
                log_error(e)

            # set up source mappings
            try:
                self._op(self.index.put_mapping, index='sources', body=self.source_mappings)
            except elasticsearch.exceptions.RequestError as e:
                log.error('Error setting Elasticsearch source mappings')
                log_error(e)

            # create an "AddToSet" script for importing accounts
            for script in self.elastic_scripts:
                self._op(self.elastic.put_script, id=script.pop('id'), body=script)
            return self._elastic

        else:
            return self._elastic


    def drop(self):
        '''
        Deletes all data from the database
        '''
        log.info('Deleting "sources" index"')
        self.index.delete(index='sources')
        log.info('Done')
        log.info('Deleting "accounts" index"')
        self.index.delete(index='accounts')
        log.info('Done')


    @property
    def index(self):

        if self._index is None:
            self._index = elasticsearch.client.IndicesClient(self.elastic)
        return self._index


    def account_stream(self, source, source_id, first_account=None):

        if first_account is not None:
            yield self._prep_account(first_account, source_id)

        for account in source:
            yield self._prep_account(account, source_id)



    @staticmethod
    def _prep_account(account, source_id):
        '''
        Formats an Account object for elastic
        '''
        doc = account.document
        doc['s'] = [source_id]
        doc_id = doc.pop('_id')
        return {
            '_op_type': 'update',
            '_id': doc_id,
            '_source': {
                "script" : {
                    "id": 'a',
                    "params" : {
                        "s" : source_id
                    }
                },
                "upsert": doc
            }
        }



    def add_accounts(self, source, chunk_size=15000, force=False):
        '''
        Given a Source object, import into the database along with all of its accounts

        chunk size benchmarks (accounts per minute):
            100 - 95,849
            200 - 173,519
            400 - 271,585
            1000 - 440,616
            2000 - 556,964
            4000 - 643,782
            10000 - 713,762
            15000 - 808,106
            20000 - 687,839
        '''

        try:

            # check to make sure there's at least one account
            try:
                first_account = next(source.__iter__())
            except StopIteration:
                log.warning(f'No accounts found in {source.file}')
                return

            # create the source and get the source ID
            new_source = self.add_source(source, import_finished=False, force=force)
            log.debug(f'New source: {str(new_source)}')

            account_stream = self.account_stream(source, new_source['source_id'], first_account=first_account)

            start_time = None

            if new_source['import_finished'] == False or force:

                while 1:
                    try:

                        bulk_results = elasticsearch.helpers.streaming_bulk(
                            #bulk_results = elasticsearch.helpers.parallel_bulk(
                            client=self.elastic,
                            #thread_count=2,
                            chunk_size=chunk_size,
                            max_retries=10,
                            raise_on_error=False,
                            raise_on_exception=False,
                            initial_backoff=2,
                            max_backoff=1024,
                            index='accounts',
                            actions=account_stream
                        )

                        for i, res in enumerate(bulk_results):

                            try:
                                if res[-1]['update']['result'] == 'created':
                                    source.unique_accounts += 1
                            except (KeyError, IndexError) as e:
                                pass
                                #log.debug(f'Invalid update result: {str(res)}')

                            if i % 100000 == 0:
                                log.debug(res)
                                if start_time is not None:
                                    time_elapsed = (datetime.now() - start_time)
                                    accounts_per_minute = int(100000 / time_elapsed.total_seconds() * 60)
                                    log.info(f'Import running at {accounts_per_minute:,} accounts per minute for {source.file}')
                                start_time = datetime.now()

                        break

                    except (
                            KeyError,
                            elasticsearch.exceptions.ConflictError,
                            elasticsearch.exceptions.SerializationError
                        ) as e:
                        # heaven only knows why this stuff happens
                        '''
                        KeyError:

                        Traceback (most recent call last):
                          File "/opt/credshed/credshed.elastic/lib/db.py", line 273, in add_accounts
                            for i, res in enumerate(bulk_results):
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/helpers/actions.py", line 231, in streaming_bulk
                            for data, (ok, info) in zip(
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/helpers/actions.py", line 153, in _process_bulk_chunk
                            bulk_data, map(methodcaller("popitem"), resp["items"])
                        KeyError: 'items'
                        '''

                        '''
                        Traceback (most recent call last):
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/serializer.py", line 93, in loads
                        return json.loads(s)
                          File "/usr/lib/python3.8/json/__init__.py", line 357, in loads
                        return _default_decoder.decode(s)
                          File "/usr/lib/python3.8/json/decoder.py", line 337, in decode
                        obj, end = self.raw_decode(s, idx=_w(s, 0).end())
                          File "/usr/lib/python3.8/json/decoder.py", line 353, in raw_decode
                        obj, end = self.scan_once(s, idx)
                        json.decoder.JSONDecodeError: Expecting ':' delimiter: line 1 column 5797 (char 5796)

                        During handling of the above exception, another exception occurred:

                        Traceback (most recent call last):
                          File "/opt/credshed/credshed.elastic/lib/db.py", line 278, in add_accounts
                        for i, res in enumerate(bulk_results):
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/helpers/actions.py", line 231, in streaming_bulk
                        for data, (ok, info) in zip(
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/helpers/actions.py", line 122, in _process_bulk_chunk
                        resp = client.bulk("\n".join(bulk_actions) + "\n", *args, **kwargs)
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/client/utils.py", line 92, in _wrapped
                        return func(*args, params=params, headers=headers, **kwargs)
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/client/__init__.py", line 457, in bulk
                        return self.transport.perform_request(
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/transport.py", line 394, in perform_request
                        data = self.deserializer.loads(
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/serializer.py", line 139, in loads
                        return deserializer.loads(s)
                          File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/serializer.py", line 95, in loads
                        raise SerializationError(s, e)
                        '''
                        log.error(f'Encountered error during bulk import, continuing')
                        log_error(e)
                        continue

            else:
                log.warning(f'Skipping {source.file.name}, already in database')

            # update counters, stats, etc.
            self.add_source(source, import_finished=True, force=force)

        except elasticsearch.exceptions.ElasticsearchException as e:
            log_error(e)
            import traceback
            log.error(traceback.format_exc())
            raise CredShedDatabaseError(e)



    def search(self, keyword, query_type='email', limit=10000, time_limit='30m'):
        '''
        Returns query stats and results in the form of a generator:
        (query_stats, <account_generator>)
        '''

        if limit == -1:
            limit = 10000

        query = self._build_query(keyword, query_type=query_type, limit=limit)

        for account in self._scan_accounts(
            index='accounts',
            time_limit=time_limit,
            query=query
        ):
            yield account


    def _op(self, func, *args, **kwargs):
        '''
        Attempt elastic operation and catch the elusive 409 error
        '''
        index = kwargs.get('index', '_all')
        tries = kwargs.pop('tries', 10)
        error = None

        for attempt in range(tries):
            try:

                return func(*args, **kwargs)

            except (KeyError, elasticsearch.exceptions.ConflictError) as e:
                # thanks obama
                '''
                Traceback (most recent call last):
                  File "/opt/credshed/credshed.elastic/lib/db.py", line 273, in add_accounts
                    for i, res in enumerate(bulk_results):
                  File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/helpers/actions.py", line 231, in streaming_bulk
                    for data, (ok, info) in zip(
                  File "/home/credshed/.local/lib/python3.8/site-packages/elasticsearch/helpers/actions.py", line 153, in _process_bulk_chunk
                    bulk_data, map(methodcaller("popitem"), resp["items"])
                KeyError: 'items'
                '''
                log.error('Encountered error in _op')
                log.critical(str(e))
                self.index.refresh(index=index)
                if attempt+1 >= tries:
                    raise CredShedDatabaseError(e)
                else:
                    log.error('Retrying...')
                    continue


    def _scan_accounts(self, index, query, time_limit):

        for result in elasticsearch.helpers.scan(
            client=self.elastic,
            index=index,
            scroll=time_limit,
            query=query
        ):
            yield Account.from_document(result['_source'])


    def count(self, keyword, query_type='email'):
        '''
        Return number of entries matched by query
        '''

        return self.query_stats(keyword, query_type=query_type)['hits']['total']['value']


    def index_size(self, index='accounts'):

        return self._op(
            self.elastic.count,
            index=index,
        )['count']


    def query_stats(self, keyword, query_type='domain'):

        query = self._build_query(keyword, limit=0, query_type=query_type)
        result = self.elastic.search(
            index='accounts',
            body=query,
        )
        return result


    def _build_query(self, keyword, limit, query_type='email'):

        query_type = validation.validate_query_type(keyword, query_type)

        if query_type == 'email':
            try:
                email, domain = keyword.lower().split('@', 1)
                domain = re.escape(domain[::-1])
                query = {
                    'size': limit,
                    'query': {
                        'bool': {
                            'must': [
                                { 'regexp': { 'd': rf'{domain}(\.[\w]+[\w\.]+)*'} },
                                # (\.[\w]+[\w\.]+)*
                                { 'term': { 'e': email } }
                            ]
                        }
                    }
                }

            except ValueError:
                raise CredShedError('Invalid email')

        elif query_type == 'domain':
            domain = keyword.lower()
            domain = re.escape(domain[::-1])

            if domain.endswith('.'):
                # if query is like ".com"
                query_regex = rf'{domain}[a-z0-9-_\.]+'
            else:
                # or if query is like "example.com"
                query_regex = rf'{domain}(\.[\w]+[\w\.]+)*'

            num_sections = len(domain.split('.'))
            query = {
                'size': limit,
                'query': {
                    'bool': {
                        'must': [
                            { 'regexp': { 'd': query_regex} }
                        ]
                    }
                }
            }

        elif query_type == 'username':
            query = {
                'size': limit,
                'query': {
                    'term': { 'u': query_regex}
                }
            }

        else:
            raise CredShedError(f'Invalid query type: {query_type}')

        log.debug(f'Result of _build_query: {query}')

        return query




    def delete_leak(self, source_id, batch_size=5000):

        if not self.meta_client:
            raise CredShedMetadataError('Removing leaks requires access to metadata. No metadata database is currently attached.')

        else:
            source = self.get_source(source_id)
            accounts_deleted = 0
            to_delete = []

            log.info('\nDeleting leak "{}{}"'.format(source.name, ':{}'.format(source.hashtype) if source.hashtype else ''))

            try:

                # delete accounts
                for result in self.accounts_metadata.find({'s': [source_id]}, {'_id': 1}):
                    to_delete.append(pymongo.DeleteOne(result))
                    if len(to_delete) % batch_size == 0:
                        accounts_deleted += self.accounts.bulk_write(to_delete, ordered=False).deleted_count
                        to_delete.clear()
                        errprint('\rDeleted {:,} accounts'.format(accounts_deleted), end='')

                if to_delete:
                    accounts_deleted += self.accounts.bulk_write(to_delete, ordered=False).deleted_count

                # delete out of tags collection
                self.accounts_metadata.delete_many({'s': [source_id]})
                # pull source ID from affected accounts
                self.accounts_metadata.update_many({'s': source_id}, {'$pull': {'s': source_id}})

                errprint('\r[+] Deleted {:,} accounts'.format(accounts_deleted), end='')

                self.sources.delete_many({'_id': source_id})


            except TypeError as e:
                log.error(str(e))
                log.error('[!] Can\'t find source "{}:{}"'.format(source.name, source.hashtype))

            errprint('')
            log.info('{:,} accounts deleted'.format(accounts_deleted))

            return accounts_deleted


    def add_source(self, source, import_finished=False, force=False):
        '''
        Inserts source details such as name, description, hash, etc.
        Returns new or existing Leak ID
        DOES NOT import accounts (use the Injestor)

        The reason we need _id AND hash is because _id is used in accounts_metadata
        to keep track of account/source associations.  the hash takes up too much space

        Meant to be called twice:
            - Once before a source is imported in order to get the Source ID
            - Again after a source is imported to update file list and account counters
        '''

        # perform costly operations outside of file lock
        source.hash
        source.file.size

        with source_lock:

            while 1:

                source.id = self.highest_source_id() + 1

                source_doc = {
                    'name': str(source.file),
                    'source_id': source.id,
                    'filename': str(source.file),
                    'files': [str(source.file)],
                    'filesize': source.file.size,
                    'description': source.description,
                    'top_domains': source.top_domains(100),
                    'top_misc_basewords': source.top_misc_basewords(100),
                    'top_password_basewords': source.top_password_basewords(100),
                    'created_date': datetime.now(),
                    'modified_date': datetime.now(),
                    'total_accounts': source.total_accounts,
                    'import_finished': import_finished
                }

                # make sure it doesn't already exist
                try:
                    existing_source = self.elastic.search(index='sources', body={
                        "query": {
                            "term": {
                                '_id': source.hash
                            }
                        }
                    })['hits']['hits'][0]['_source']

                except (IndexError, KeyError) as e:
                    log.debug(f'{source.file} not yet in DB')
                    
                    # create the source
                    res = self._op(
                        self.elastic.create,
                        index='sources',
                        id=source.hash,
                        body=source_doc,
                        refresh=True,
                    )

                    log.debug(f'source creation result: {str(res)}')

                    return source_doc


                log.debug(f'Matching hash already exists for {source.file}, updating...')
                log.debug(f'existing_source: {str(existing_source)}')

                # add filename
                res = self._op(
                    self.elastic.update,
                    index='sources',
                    id=source.hash,
                    body={
                        'script' : {
                            'id': 'UpdateSourceFilenames',
                            'params' : {
                                'filename': str(source.file),
                            }
                        }
                    }
                )

                # if the import hasn't already finished, or if we're forcing it
                if existing_source['import_finished'] == False or force:

                    # if an import finished at any point in time, we need to make sure this is True
                    source_doc['import_finished'] = (import_finished or existing_source['import_finished']) 

                    # add filename and update total accounts
                    # note: only updates value if it's larger than the existing one
                    res = self._op(
                        self.elastic.update,
                        index='sources',
                        id=source.hash,
                        body={
                            'script' : {
                                'id': 'UpdateSourceCounters',
                                'params' : {
                                    'total_accounts': source.total_accounts,
                                }
                            }
                        }
                    )

                    log.debug(f'Updated source filenames & counters: {str(res)}')

                    # update modified date and set import status
                    res = self._op(
                        self.elastic.update,
                        index='sources',
                        id=source.hash,
                        body={
                            'doc': {
                                'modified_date': datetime.now(),
                                'import_finished': (import_finished or existing_source['import_finished']),

                            }
                        }
                    )

                    log.debug(f'Updated source modified date and import status: {str(res)}')

                    # only update these if import finished successfully
                    # this prevents messing up existing data when cancelling an import operation
                    if import_finished:

                        # delete the source if the import finished and there still aren't any accounts
                        if source.total_accounts == 0:
                            log.info(f'Import finished but no accounts found; deleting source {source.file}')
                            res = self._op(
                                self.elastic.delete,
                                index='sources', id=source.hash
                            )
                            log.debug(f'Source deletion result: {str(res)}')

                        else:

                            log.debug('Updating source now that import has finished')

                            res = self._op(
                                self.elastic.update,
                                index='sources',
                                id=source.hash,
                                body={
                                    'doc': {
                                        'total_accounts': source.total_accounts,
                                        'top_domains': source.top_domains(100),
                                        'top_misc_basewords': source.top_misc_basewords(100),
                                        'top_password_basewords': source.top_password_basewords(100),
                                    }
                                }
                            )

                            log.debug(f'source update result (import finished): {str(res)}')

                else:
                    log.warning(f'Import already finished for {source.file}, skipping')

                # force refresh on source index
                self.index.refresh(index='sources')
                return existing_source


    def highest_source_id(self):
        '''
        returns source with highest ID
        or 1 if there are no leaks loaded
        '''

        log.debug(f'Getting highest source ID')

        try:
            res = int(self._op(
                self.elastic.search,
                index='sources',
                size=1,
                sort=[
                    'source_id:desc'
                ]
            )['hits']['hits'][0]['_source']['source_id'])

        except (elasticsearch.exceptions.ElasticsearchException, KeyError, IndexError, ValueError) as e:
            log.debug(f'Failed to get source ID: {str(e)[:100]}')
            log.debug(f'Defaulting to 1')
            res = 1

        return int(res)



    def get_source(self, source_id):

        try:
            doc = self.sources.find_one({'_id': int(source_id)})
            if doc:
                return Source.from_doc(doc)
            else:
                raise CredShedError(f'No source found with ID "{source_id}"')

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def optimize_for_indexing(self, reset=False):
        '''
        Temporarily disables replication and index refresh and tunes for max indexing speed
        '''

        if not reset:
            log.info('Optimizing elasticsearch for import')
            
            log.info('Disabling replication and refresh')
            self._op(
                self.elastic.indices.put_settings,
                index='accounts',
                body={
                    'number_of_replicas': 0,
                    'refresh_interval': -1
                }
            )
        '''
        else:
            log.debug('Import finished, resetting elasticsearch settings')
            
            log.debug('Re-enabling replication and index refresh')
            self._op(
                self.elastic.indices.put_settings,
                index='accounts',
                body={
                    "number_of_replicas": 1,
                    'refresh_interval': '1s'
                }
            )
        '''