#!/usr/bin/env python3

# by TheTechromancer

from .errors import *
from .parser import *
from pathlib import Path
from .config import config
from datetime import datetime


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


    @classmethod
    def from_doc(cls, doc):
        '''
        Create a Source() object from a dictionary
        '''

        try:
            c = cls(doc.pop('files')[0], filesize=doc.pop('filesize'))
            c.update(doc)
            return c
        except (KeyError, IndexError) as e:
            raise CredShedSourceError(f'Failed to create Source object from db: {e}')


    def __init__(self, filename, filesize=None, deduplicate=False):

        # Not set unless retrieved from DB
        self.id = None

        # filename from which accounts are extracted
        self.filename = Path(filename).resolve()
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

        allowed_fields = ['name', 'hash', 'description', 'created_date', 'modified_date', 'total_accounts', 'unique_accounts']

        self.id = d.pop('_id')
        for k,v in d.items():
            if k in allowed_fields:
                self.__dict__.update({k:v})



    def __iter__(self):

        for account in self.accounts:
            yield account


    def __str__(self):

        return f'{self.filename} (unique accounts: {len(self):,})'


    def __len__(self):

        length = len(self.accounts)
        if length > 0:
            return length
        else:
            return self.unique_accounts