#!/usr/bin/env python3

# by TheTechromancer

import copy
import queue
import hashlib
import logging
import pymongo
import itertools
import traceback
from .util import *
from .errors import *
from .source import *
from .account import *
from time import sleep
from pathlib import Path
from .config import config
from datetime import datetime, timedelta


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

        #self.accounts.create_index([('username', pymongo.ASCENDING)], sparse=True, background=True)
        #self.accounts.create_index([('email', pymongo.ASCENDING)], sparse=True, background=True)

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




    def search(self, keywords, query_type='email', max_results=10000):
        '''
        searches by keyword using regex
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

                    query_regex = rf'^{query_str}.*'
                    query = {'_id': {'$regex': query_regex}}
                    log.info(f'Raw mongo query: {query}')
                    results['emails'] = self.accounts.find(query).limit(max_results)
                    #results['emails'] = self.accounts.find({'email': email, '_id': {'$regex': domain_regex}})
                    #results['emails'] = self.accounts.find({'email': email})

                except ValueError:
                    raise CredShedError('Invalid email')
                    # assume email without domain
                    '''
                    email = r'^{}$'.format(keyword.lower())
                    query = {'email': {'$regex': email}}
                    log.info(query)
                    results['emails'] = self.accounts.find(query).limit(max_results)
                    '''


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
                log.info(f'Raw mongo query: {query}')
                results['emails'] = self.accounts.find(query).limit(max_results)

            elif query_type == 'username':
                query_regex = rf'^{re.escape(keyword)}$'
                query = {'username': {'$regex': query_regex}}
                log.info(f'Raw mongo query: {query}')
                results['usernames'] = self.accounts.find(query).limit(max_results)

            else:
                raise CredShedError(f'Invalid query type: {query_type}')

            for category in results:
                for result in results[category]:
                    try:
                        account = Account.from_document(result)
                        yield account
                    except AccountCreationError as e:
                        log.warning(str(e))
            


    def fetch_account_metadata(self, account):

        if not self.meta_client:
            raise CredShedMetadataError('No metadata available')

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

        # see if it already exists - try to find by hash
        source_in_db = self.sources.find_one({'hash': source.hash})

        # if it doesn't exist, create it
        if source_in_db is None:

            id_counter = self._make_source_id()

            source_doc = {
                'name': str(source.filename),
                'hash': source.hash,
                'files': [str(source.filename)],
                'filesize': source.filesize,
                'description': source.description,
                'created_date': datetime.now(),
                'modified_date': datetime.now(),
                'total_accounts': (source.total_accounts if import_finished else 0),
                'unique_accounts': (source.unique_accounts if import_finished else 0),
                'import_finished': (True if import_finished else False)
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

            if import_finished:
                self.sources.update_one({'hash': source.hash}, {
                    '$addToSet': {
                        'files': str(source.filename)
                    },
                    '$set': {
                        'modified_date': datetime.now(),
                        'total_accounts': source.total_accounts,
                        'import_finished': True
                    },
                    '$inc': {
                        'unique_accounts': source.unique_accounts
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



    def get_source(self, _id):

        try:
            doc = self.sources.find_one({'_id': int(_id)})
            return Source.from_doc(doc)

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