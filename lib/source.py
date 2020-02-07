#!/usr/bin/env python3

# by TheTechromancer

from .errors import *
from .parser import *
from .util import decode
from pathlib import Path
from .config import config
from datetime import datetime
from .validation import word_regex


# set up logging
log = logging.getLogger('credshed.source')



class Source():
    '''
    Source = a source of data, typically a file.  One leak can have many sources

    1. Give it a filename:
        l = Source('dump.txt')
    2. Parse
        l.parse()
    3. Iterate
        for account in l:
            print(account)
    '''

    # fields which are allowed in the JSON document
    doc_fields = ['hash', 'name', 'filename', 'files', 'filesize', 'description', 'top_domains', 'top_words', 'created_date', 'modified_date', 'total_accounts', 'unique_accounts', 'import_finished']


    @classmethod
    def from_doc(cls, doc):
        '''
        Create a Source() object from a dictionary
        '''

        try:
            c = cls(doc.pop('filename'), name=doc.pop('name'), filesize=doc.pop('filesize'))
            c.update(doc)
            return c
        except (KeyError, IndexError) as e:
            raise CredShedSourceError(f'Failed to create Source object from db: {e}')


    def __init__(self, filename, name=None, filesize=None, deduplicate=False):

        # Not set unless retrieved from DB
        self.id = None

        # filename from which accounts are extracted
        self.filename = Path(filename).resolve()
        if name is None:
            self.name = str(self.filename)
        else:
            self.name = name
        # filesize in bytes
        if filesize is None:
            try:
                self.filesize = filestore.size(filename)
            except FilestoreUtilError as e:
                log.error(e)
                self.filesize = 0
        # set used for account deduplication
        self.accounts = set()
        # keeps track of unique accounts during import
        self.unique_accounts = 0
        # keeps track of total accounts during import
        self.total_accounts = 0
        # whether or not to deduplicate accounts (collects accounts immediately into memory rather than lazily)
        self.deduplicate = deduplicate
        # description for source
        self.description = ''
        # SHA1 hash of file
        self._hash = None
        # top domains
        self.domains = {}
        # top password base words
        self.words = {}


    def to_doc(self):

        doc = dict()
        for field in self.doc_fields:
            if field in self.__dict__:
                doc.update({field: self.__dict__[field]})
        doc['id'] = self.id

        return doc



    def parse(self, unattended=True):

        if unattended:
            self.description = f'Unattended import at {datetime.now().isoformat(timespec="milliseconds")}'
        else:
            self.description = f'Manual import at {datetime.now().isoformat(timespec="milliseconds")}'

        try:
            accounts = TextParse(self.filename, unattended=unattended)
        except TextParseError as e:
            log.warning(f'{self.filename} falling back to non-strict mode')
            accounts = TextParse(self.filename, unattended=unattended, strict=False)

        if self.deduplicate:
            for account in accounts:
                self.accounts.add(account)
        else:
            self.accounts = accounts


    @property
    def hash(self):

        if self._hash is None:
            self._hash = hash_file(self.filename)
        return self._hash


    def update(self, d):

        self.id = d.pop('_id')
        for k,v in d.items():
            if k in self.doc_fields:
                self.__dict__.update({k:v})


    def increment(self, account):

        _, domain = account.split_email
        if domain:
            try:
                self.domains[domain] += 1
            except KeyError:
                self.domains[domain] = 1

        if account.password:
            for word in word_regex.findall(account.password):
                word = word.lower()
                try:
                    self.words[word] += 1
                except KeyError:
                    self.words[word] = 1

        self.total_accounts += 1


    def top_domains(self, limit=10):

        sorted_domains = dict(sorted(self.domains.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {decode(d): c for d,c in sorted_domains.items()}


    def top_words(self, limit=10):

        sorted_words = dict(sorted(self.words.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {decode(w): c for w,c in sorted_words.items()}


    def __iter__(self):

        for account in self.accounts:
            yield account


    def __str__(self):

        try:
            store_dir = config['FILESTORE']['store_dir']
            filename = self.filename.relative_to(store_dir)
        except (KeyError, ValueError):
            filename = self.filename

        return f'{filename} (total accounts: {len(self):,})'


    def __len__(self):

        length = len(self.accounts)
        if length > 0:
            return length
        else:
            return self.total_accounts