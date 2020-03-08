#!/usr/bin/env python3

# by TheTechromancer

import hashlib
import logging
import pymongo
from .util import *
from .errors import *
from .source import *
from .account import *
from time import sleep
from . import validation
from .config import config
from datetime import datetime


# set up logging
log = logging.getLogger('credshed.db')


class DB():

    def __init__(self):

        # set up main database (for accounts)
        try:
            self.main_client = self._get_main_client()
            self.main_db = self.main_client[self.main_db_name]
            self.accounts = self.main_db.accounts
        except CredShedError as e:
            self.main_client = None
            log.error(f'Error setting up main database: {e}')

        # set up meta database (for account metadata)
        try:
            self.meta_client = self._get_meta_client()
            self.meta_db = self.meta_client[self.meta_db_name]
            self.accounts_metadata = self.meta_db.accounts_metadata
        except CredShedError as e:
            self.meta_client = None
            log.error(f'Error setting up meta database: {e}')

        if not (self.main_client or self.meta_client):
            raise CredShedDatabaseError('Failed to contact both main and metadata databases')

        #self.accounts.create_index([('u', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('e', pymongo.ASCENDING)], sparse=True, background=True)

        # sources
        self.sources = self.main_db.sources



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

        try:

            query = self._build_query(keyword, query_type)

            for result in self.accounts.find(query).limit(limit):
                try:
                    account = Account.from_document(result)
                    yield account
                except AccountCreationError as e:
                    log.warning(str(e))

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))




    def count(self, keyword, query_type='email'):

        try:

            query = self._build_query(keyword, query_type)
            return self.accounts.count_documents(query)

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def query_stats(self, keyword, query_type='domain'):

        if self.meta_client:

            try:

                # {source_id: num_accounts}
                sources = dict()

                query = self._build_query(keyword, query_type)
                for result in self.accounts_metadata.find(query, {'s': True, '_id': False}):

                    try:
                        for source_id in result['s']:
                            try:
                                sources[source_id] += 1
                            except KeyError:
                                sources[source_id] = 1

                    except KeyError:
                        log.error('"s" key missing from account metadata')

                return sources

            except pymongo.errors.PyMongoError as e:
                raise CredShedDatabaseError(error_detail(e))

        else:
            raise CredShedMetadataError('No metadata available, check database config')




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
            


    def fetch_account_metadata(self, account):

        if not self.meta_client:
            raise CredShedMetadataError('No metadata available, check database config')

        sources = []

        try:

            _id = ''
            if type(account) == str:
                _id = account
            elif type(account) == Account:
                _id = account._id
            else:
                raise TypeError

            source_ids = self.accounts_metadata.find_one({'_id': _id})['s']

            for source_id in source_ids:
                try:
                    sources.append(self.get_source(source_id))
                except CredShedDatabaseError:
                    log.warning(f'No database entry found for source ID {source_id}')
                    continue

        except KeyError as e:
            raise CredShedError(f'Error retrieving source IDs from account "{_id}": {e}')
        except TypeError as e:
            pass
            #log.debug('No source IDs found for account ID "{}": {}'.format(str(_id), str(e)))

        account_metadata = AccountMetadata(sources)
        return account_metadata




    def delete_leak(self, source_id, batch_size=10000):

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


    def add_source(self, source, import_finished=False):
        '''
        Inserts source details such as name, description, hash, etc.
        Returns new or existing Leak ID
        DOES NOT import accounts (use the Injestor)

        The reason we need _id AND hash is because _id is used in accounts_metadata to keep track of account/source associations

        Meant to be called twice:
            - Once before a source is imported in order to get the Source ID
            - Again after a source is imported to update file list and unique account counters
        '''

        try:
            # see if it already exists - try to find by hash
            source_in_db = self.sources.find_one({'hash': source.hash})
        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))

        # if it doesn't exist, create it
        if source_in_db is None:

            id_counter = self._make_source_id()

            source_doc = {
                'name': str(source.filename),
                'filename': str(source.filename),
                'hash': source.hash,
                'files': [str(source.filename)],
                'filesize': source.filesize,
                'description': source.description,
                'top_domains': source.top_domains(100),
                'top_misc_basewords': source.top_misc_basewords(100),
                'top_password_basewords': source.top_password_basewords(100),
                'created_date': datetime.now(),
                'modified_date': datetime.now(),
                'total_accounts': source.total_accounts,
                'unique_accounts': source.unique_accounts,
                'import_finished': import_finished
            }

            while 1:
                try:
                    source_doc['_id'] = id_counter
                    self.sources.insert_one(source_doc)                       
                    break

                except pymongo.errors.DuplicateKeyError:
                    id_counter += 1
                    continue

                except pymongo.errors.PyMongoError as e:
                    raise CredShedDatabaseError(error_detail(e))
                    break

            return source_doc

        # otherwise, update it
        else:
            # log.info(f'Matching hash for {self.filename} found')

            self.sources.update_one({'hash': source.hash}, {
                '$addToSet': {
                    'files': str(source.filename)
                },
                '$set': {
                    'modified_date': datetime.now(),
                    'import_finished': import_finished
                },
                '$max': {
                    'total_accounts': source.total_accounts,
                },
                '$inc': {
                    'unique_accounts': source.unique_accounts
                }

            })

            # only update the top domains if import finished successfully
            # this prevents messing up existing data when cancelling an import operation
            if import_finished:
                self.sources.update_one({'hash': source.hash}, {
                    '$set': {
                        'top_domains': source.top_domains(100),
                        'top_misc_basewords': source.top_misc_basewords(100),
                        'top_password_basewords': source.top_password_basewords(100),
                    }
                })

            # refresh data   
            source_in_db = self.sources.find_one({'_id': source_in_db['_id']})
            return source_in_db




    def _make_source_id(self):

        # get the highest source._id
        id_counter = self.highest_source_id()

        # make double-sure it doesn't exist yet
        while 1:
            try:
                id_counter += 1
                result = self.sources.find_one({'_id': id_counter})
                if not result:
                    return id_counter
            except pymongo.errors.PyMongoError as e:
                raise CredShedDatabaseError(error_detail(e))
                continue




    def stats(self, accounts=False, sources=True, db=False):
        '''
        prints database statistics
        returns most recently added source ID, if applicable
        '''

        highest_source_id = 0
        stats = []

        try:

            if accounts:
                accounts_stats = self.main_db.command('collstats', 'accounts', scale=1048576)
                stats.append('[+] Account Stats (MB):')
                for k, v in accounts_stats.items():
                    if k not in ['wiredTiger', 'indexDetails', 'shards', 'raw']:
                        stats.append(f'\t{k}: {v}')
            stats.append('')

            if sources:

                all_sources = self.sources.find({})

                if all_sources:
                    stats.append('[+] Leaks in DB:')

                    for s in all_sources:
                        try:
                            if s['total_accounts'] > 0:
                                num_files = len(s['files'])
                                source_str = '{}: {} ({:,} accounts, {}, {})'.format(
                                    s['_id'],
                                    s['name'],
                                    s['total_accounts'],
                                    f'{num_files:,} ' + ('files' if num_files > 1 else 'file'),
                                    bytes_to_human(s['filesize'])
                                )
                                stats.append(source_str)

                        except KeyError as e:
                            log.error(f'Missing key "{e}" in source ID {s["_id"]}')

                    stats.append('')

        except pymongo.errors.OperationFailure:
            stats.append('[!] No accounts added yet\n')

        except pymongo.errors.PyMongoError as e:
            log.error(error_detail(e))

        if db:
            db_stats = self.main_db.command('dbstats', scale=1048576)
            stats.append('[+] DB Stats (MB):')
            for k in db_stats:
                if k not in ['raw']:
                    stats.append('\t{}: {}'.format(k, db_stats[k]))

        return '\n'.join(stats)



    def highest_source_id(self):
        '''
        returns source with highest ID
        or 1 if there are no leaks loaded
        '''

        # get the highest source._id
        try:
            id_counter = next(self.sources.find({}, {'_id': 1}, sort=[('_id', -1)], limit=1))['_id']
        except StopIteration:
            id_counter = 1

        return max(1, id_counter)



    def account_count(self):

        try:
            collstats = self.main_db.command('collstats', 'accounts', scale=1048576)
            num_accounts_in_db = collstats['count']
        except KeyError:
            num_accounts_in_db = 0
        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))

        return int(num_accounts_in_db)



    def get_source(self, source_id):

        try:
            doc = self.sources.find_one({'_id': int(source_id)})
            if doc:
                return Source.from_doc(doc)
            else:
                raise CredShedError(f'No source found with ID "{source_id}"')

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))



    def close(self):

        try:
            self.main_client.close()
        except AttributeError:
            pass
        try:
            self.meta_client.close()
        except AttributeError:
            pass


    def add_accounts(self, batch, source_id, tries=3):
        '''
        accepts a list of Account() objects
        returns unique (new) Account() objects
        if error was encountered, returns dictionary:
            {'errors': [error1, error2, ...]}
        '''

        tries_left = int(tries)
        errors = []

        while tries_left:

            try:

                upserted_accounts = dict()
                if self.meta_client:
                    self._mongo_meta_add_batch(batch, source_id)
                if self.main_client:
                    upserted_accounts = self._mongo_main_add_batch(batch)

                return upserted_accounts

            except pymongo.errors.PyMongoError as e:
                tries_left -= 1
                sleep(5)
                errors.append(error_detail(e))

        raise CredShedBatchError(f'Failed to add batch after {tries} tries ():\n' + "\n".join(errors))
        return {'errors': errors}



    def _mongo_main_add_batch(self, batch):


        unique_accounts = 0
        mongo_batch = []

        # all_accounts holds {account_id: account} since the mongo result only includes the ID
        all_accounts = dict()
        upserted_accounts = dict()

        for account in batch:
            account_doc = account.document
            _id = account_doc.pop('_id')
            mongo_batch.append(pymongo.UpdateOne({'_id': _id}, {'$setOnInsert': account_doc}, upsert=True))
            all_accounts[_id] = account

        for _id in self.accounts.bulk_write(mongo_batch, ordered=False).upserted_ids.values():
            upserted_accounts[_id] = None

        # remove any account which is not unique
        for _id in upserted_accounts.keys():
            try:
                upserted_accounts[_id] = all_accounts.pop(_id)
            except KeyError:
                continue

        return list(upserted_accounts.values())



    def _mongo_meta_add_batch(self, batch, source_id):

        mongo_batch = []

        for account in batch:
            _id = account._id
            mongo_batch.append(pymongo.UpdateOne({'_id': _id}, {'$addToSet': {'s': source_id}}, upsert=True))

        result = self.accounts_metadata.bulk_write(mongo_batch, ordered=False)
        return result



    def _get_main_client(self):

        try:

            try:
                main_server = config['MONGO PRIMARY']['server']
                main_port = int(config['MONGO PRIMARY']['port'])
                self.main_db_name = config['MONGO PRIMARY']['db']
                mongo_user = config['MONGO GLOBAL']['user']
                mongo_pass = config['MONGO GLOBAL']['pass']
            except KeyError as e:
                raise CredShedConfigError(str(e))

            # main DB
            mongo_client = pymongo.MongoClient(main_server, main_port, username=mongo_user, password=mongo_pass)
            return mongo_client

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))


    def _get_meta_client(self):

        try:

            try:
                meta_server = config['MONGO METADATA']['server']
                meta_port = int(config['MONGO METADATA']['port'])
                self.meta_db_name = config['MONGO METADATA']['db']
                mongo_user = config['MONGO GLOBAL']['user']
                mongo_pass = config['MONGO GLOBAL']['pass']
            except KeyError as e:
                raise CredShedConfigError(str(e))

            # meta DB (account metadata including source information, leak <--> account associations, etc.)
            mongo_client = pymongo.MongoClient(meta_server, meta_port, username=mongo_user, password=mongo_pass)
            return mongo_client

        except pymongo.errors.PyMongoError as e:
            raise CredShedDatabaseError(error_detail(e))


    def __enter__(self):

        return self


    def __exit__(self, exception_type, exception_value, traceback):

        self.close()