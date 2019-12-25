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

    def __init__(self, filename, deduplicate=False):

        # Not set unless retrieved from DB
        self.id = None

        # filename from which accounts are extracted
        self.filename = Path(filename).resolve()
        # filesize in bytes
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


    def __iter__(self):

        for account in self.accounts:
            yield account


    def __str__(self):

        s  = '{}:\n'.format(self.filename)
        s += '  unique accounts: {:,}'.format(len(self))

        return s


    def __len__(self):

        try:
            return len(self.accounts)
        except TypeError:
            return 0