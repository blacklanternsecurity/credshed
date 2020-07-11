#!/usr/bin/env python3

# by TheTechromancer

import re
import logging
import pymongo
from .util import *
from . import logger
from .errors import *
from .source import *
from .account import *
from . import validation
from .config import config
from datetime import datetime
from multiprocessing import Manager


# set up logging
log = logging.getLogger('credshed.db')


source_lock = Manager().Semaphore()


class DB():


    def __init__(self):

        try:
            self.client = self._get_client()
            self.db = self.client[self.db_name]
            self.accounts = self.db.accounts.with_options(
                write_concern=pymongo.write_concern.WriteConcern(
                    w=0,
                    j=False,
                    fsync=False
                ),
            )
        except CredShedError as e:
            raise CredShedDatabaseError('Failed to contact database')            

        # sources
        self.sources = self.db.sources

        # create indexes
        #self.sources.create_index([('source_id', pymongo.ASCENDING)], background=True)
        #self.accounts.create_index([('u', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('e', pymongo.ASCENDING)], sparse=True, background=True)


    def drop(self):
        '''
        Deletes all data from the database
        '''
        log.info('Deleting "sources" collection"')
        self.sources.delete_many({})
        log.info('Deleting "accounts" collection"')
        self.accounts.delete_many({})
        log.info('Done')




    def find_one(self, _id):
        '''
        retrieves one account by id
        '''

        try:
            return Account.from_document(self.accounts.find({'_id': _id}).next())
        except (pymongo.errors.PyMongoError, StopIteration) as e:
            raise CredShedDatabaseError(error_detail(e))



    def search(self, keyword, query_type='email', limit=10000):
        '''
        searches by keyword using regex
        ~ 2 minutes to regex-search non-indexed 100M-entry DB
        '''

        query = self._build_query(keyword, query_type)

        for result in self._op(
                self.accounts.find,
                query
            ):
            try:
                account = Account.from_document(result)
                yield account
            except AccountCreationError as e:
                log.warning(str(e))
                #import traceback
                #log.warning(traceback.format_exc())
                log.warning(result)


    def count(self, keyword, query_type='email'):

        try:

            query = self._build_query(keyword, query_type)
            return self.accounts.count_documents(query)

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def account_count(self):

        try:
            collstats = self.db.command('collstats', 'accounts', scale=1048576)
            num_accounts_in_db = collstats['count']
        except KeyError:
            num_accounts_in_db = 0
        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))

        return int(num_accounts_in_db)




    def query_stats(self, keyword, query_type='domain'):

        # {source_id: num_accounts}
        sources = dict()

        query = self._build_query(keyword, query_type)
        for result in self._op(
                self.accounts.find,
                query, {'s': True, '_id': False}
            ):

            try:
                for source_id in result['s']:
                    try:
                        sources[source_id] += 1
                    except KeyError:
                        sources[source_id] = 1

            except KeyError:
                log.error('"s" key missing from account metadata')

        return sources



    def _build_query(self, keyword, query_type='email'):


        query_type = validation.validate_query_type(keyword, query_type)

        if query_type == 'email':
            try:
                email, domain = keyword.lower().split('@')[:2]
                # _id begins with reversed domain
                domain_chunk = re.escape(domain[::-1])
                email_hash = decode(base64.b64encode(hashlib.sha256(encode(email)).digest()[:6]))
                query_str = domain_chunk + '\\|' +  re.escape(email_hash)

                query_regex = rf'^{query_str}.*'
                query = {'_id': {'$regex': query_regex}}

            except ValueError:
                raise CredShedError('Invalid email')

        elif query_type == 'domain':
            domain = keyword.lower()
            domain = re.escape(domain[::-1])

            if domain.endswith('.'):
                # if query is like ".com"
                query_regex = rf'^{domain}[\w.]*\|'
            else:
                # or if query is like "example.com"
                query_regex = rf'^{domain}[\.\|]'

            num_sections = len(domain.split('.'))
            query = {'_id': {'$regex': query_regex}}

        elif query_type == 'username':
            query_regex = rf'^{re.escape(keyword)}$'
            query = {'u': {'$regex': query_regex}}

        else:
            raise CredShedError(f'Invalid query type: {query_type}')

        log.debug(f'Raw mongo query: {query}')
        return query



    def add_accounts(self, source, force=False, batch_size=1000):
        '''
        Given a Source object, import into the database along with all of its accounts

        https://www.percona.com/blog/2020/05/05/tuning-mongodb-for-bulk-loads/
        '''

        try:
            client = self._get_client()
            db = client[self.db_name]
            accounts_collection = db.accounts.with_options(
                write_concern=pymongo.write_concern.WriteConcern(
                    w=0,
                    j=False,
                    fsync=False
                ),
            )
        except CredShedError as e:
            raise CredShedDatabaseError(f'Failed to contact database: {e}')

        # check to make sure there's at least one account
        try:
            first_account = next(source.__iter__())
        except StopIteration:
            log.warning(f'No accounts found in {source.file}')
            return

        # create the source and get the source ID
        new_source = self.add_source(source, import_finished=False, force=force, client=client)
        log.debug(f'New source: {str(new_source)}')

        account_stream = self.account_stream(
            source,
            first_account=first_account,
            batch_size=batch_size
        )

        progress_increment = max(1, int(100000 / batch_size))
        start_time = datetime.now()

        if new_source['import_finished'] == False or force:

            for i, batch in enumerate(account_stream):
                seconds_start_time = datetime.now()
                self._op(
                    accounts_collection.bulk_write,
                    batch,
                    ordered=False
                )
                seconds_end_time = datetime.now()

                seconds_elapsed = (seconds_end_time - seconds_start_time).total_seconds()
                accounts_per_second = int(batch_size / seconds_elapsed)
                if accounts_per_second < 200:
                    log.warning(f'Detected significant throttling for {source.file.name}')
                    #sleep(300)

                if (i != 0 ) and (i % progress_increment == 0):
                    minutes_elapsed = (datetime.now() - start_time).total_seconds() / 60
                    accounts_per_minute = int(100000 / minutes_elapsed)
                    log.info(f'Import running at {accounts_per_minute:,} accounts per minute for {source.file}')
                    start_time = datetime.now()

        else:
            log.warning(f'Skipping {source.file.name}, already in database')

        # update counters, stats, etc.
        self.add_source(source, import_finished=True, force=force, client=client)



    def _op(self, func, *args, **kwargs):
        '''
        automatically retries, handling pymongo errors
        '''
        tries = kwargs.pop('tries', 10)
        error = None

        for attempt in range(tries):
            try:

                return func(*args, **kwargs)

            except pymongo.errors.PyMongoError as e:
                log.error('Encountered error in DB._op()')
                log.error(error_detail(e))
                if attempt+1 >= tries:
                    raise CredShedDatabaseError(e)
                else:
                    log.error('Retrying...')
                    continue



    def account_stream(self, source, first_account=None, batch_size=5000):

        batch = []

        if first_account is not None:
            batch.append(self._account_insert_op(first_account, source.id))

        for account in source:
            batch.append(self._account_insert_op(account, source.id))

            if len(batch) >= batch_size:
                yield batch
                batch = []

        if batch:
            yield batch



    @staticmethod
    def _account_insert_op(account, source_id):
        '''
        Formats an Account object for insert
        '''
        account_doc = account.document
        _id = account_doc.pop('_id')

        op = (
            pymongo.UpdateOne(
                {'_id': _id},
                {
                    '$setOnInsert': account_doc,
                    '$addToSet': {'s': source_id}
                },
                upsert=True
            )
        )

        return op



    def delete_leak(self, source_id, batch_size=5000):

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


    def add_source(self, source, import_finished=False, force=False, client=None):
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

        if client is None:
            client = self.client

        db = client[self.db_name]
        sources = db.sources

        # perform costly operations outside of file lock
        source.hash
        source.file.size

        source.id = self.highest_source_id(client=client) + 1

        source_doc = {
            '_id': source.hash,
            'name': str(source.file),
            'source_id': source.id,
            'filename': str(source.file),
            'files': [str(source.file)],
            'filesize': source.file.size,
            'description': source.description,
            'top_domains': {
                k.replace('.', '|'): v for k,v in source.top_domains(100).items()
            },
            'top_misc_basewords': source.top_misc_basewords(100),
            'top_password_basewords': source.top_password_basewords(100),
            'created_date': datetime.now(),
            'modified_date': datetime.now(),
            'total_accounts': source.total_accounts,
            'import_finished': import_finished
        }

        # make sure it doesn't already exist
        existing_source = self._op(
            sources.find_one,
            {'_id': source.hash}
        )

        if existing_source is None:
            log.debug(f'{source.file} not yet in DB')
            
            while 1:
                # create the source
                try:
                    self._op(
                        sources.insert_one,
                        source_doc
                    )
                    return source_doc

                except pymongo.errors.DuplicateKeyError:
                    source.id += 1
                    source_doc['source_id'] = source.id
                    continue

                except pymongo.errors.PyMongoError as e:
                    raise CredShedDatabaseError(error_detail(e))


        log.debug(f'Matching hash already exists for {source.file}, updating...')
        log.debug(f'existing_source: {str(existing_source)}')

        self._op(
            sources.update_one,
            {'hash': source.hash}, {
                '$addToSet': {
                    'files': str(source.name)
                },
                '$set': {
                    'modified_date': datetime.now(),
                    'import_finished': (import_finished or existing_source['import_finished'])
                },
                '$max': {
                    'total_accounts': source.total_accounts,
                }
            }
        )

        # only update these if import finished successfully
        # this prevents messing up existing data when cancelling an import operation
        if import_finished and (existing_source['import_finished'] == False or force):

            self._op(
                sources.update_one,
                {'hash': source.hash}, {
                    '$set': {
                        'top_domains': source.top_domains(100),
                        'top_misc_basewords': source.top_misc_basewords(100),
                        'top_password_basewords': source.top_password_basewords(100),
                    }
                }
            )

        # refresh data
        refreshed_source = self._op(
            sources.find_one,
            {'_id': source.id}
        )

        if refreshed_source is None:
            # if this happens, the source just got deleted
            return existing_source
        else:
            return refreshed_source


    def highest_source_id(self, client=None):
        '''
        returns source with highest ID
        or 1 if there are no leaks loaded
        '''

        if client is None:
            client = self.client

        # get the highest source._id
        try:
            id_counter = next(self._op(
                self.sources.find,
                {},
                {'source_id': 1},
                sort=[('_id', -1)],
                limit=1)
            )['source_id']
        except StopIteration:
            id_counter = 1

        return max(1, id_counter)


    def get_source(self, source_id):

        try:
            doc = self.sources.find_one({'_id': int(source_id)})
            if doc:
                return Source.from_doc(doc)
            else:
                raise CredShedError(f'No source found with ID "{source_id}"')

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def _get_client(self, bulk=True):

        try:

            try:
                main_server = config['MONGO']['server']
                main_port = int(config['MONGO']['port'])
                self.db_name = config['MONGO']['db']
                mongo_user = config['MONGO']['user']
                mongo_pass = config['MONGO']['pass']
            except KeyError as e:
                raise CredShedConfigError(str(e))

            return pymongo.MongoClient(
                main_server,
                main_port,
                username=mongo_user,
                password=mongo_pass
            )

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def close(self):

        try:
            self.client.close()
        except AttributeError:
            pass


    def __enter__(self):

        return self


    def __exit__(self, exception_type, exception_value, traceback):

        self.close()