#!/usr/bin/env python3

# by TheTechromancer

from .util import *
from .errors import *
from .parser import *
from pathlib import Path
from .filestore import *
from .config import config
from datetime import datetime
from .parser.file import File
from .validation import word_regex


# set up logging
log = logging.getLogger('credshed.source')



class Source():
    '''
    Source = a source of data, typically a file.  Deduplicated by file hash, so one source can have multiple files of the same hash

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
            c = cls(doc.pop('filename'), name=doc.pop('name'), filesize=doc.pop('filesize'))
            #c.update(doc)
            for k,v in doc.items():
                setattr(c,k,v)
            return c
        except (KeyError, IndexError) as e:
            raise CredShedSourceError(f'Failed to create Source object from db: {e}')


    def __init__(self, file, name=None, filesize=None, deduplicate=False):

        # Not set unless retrieved from DB
        self.id = None

        # filename from which accounts are extracted
        self.file = File(file)
        if name is None:
            self.name = str(self.file)
        else:
            self.name = name

        if filesize is not None and self.file._size is None:
            self.file._size = filesize

        # set used for account deduplication
        self._accounts = set()
        # keeps track of total accounts during import
        self.total_accounts = 0
        # how many never-before-seen accounts have been imported (for runtime user feedback only, not stored)
        self.unique_accounts = 0
        # whether or not to deduplicate accounts (collects accounts immediately into memory rather than lazily)
        self.deduplicate = deduplicate
        # description for source
        self.description = ''
        # SHA1 hash of file
        self._hash = None
        # top domains
        self.domains = {}
        # top base words from passwords
        self.password_basewords = {}
        # top base words from misc/description field
        self.misc_basewords = {}



    def parse(self, unattended=True, force_ascii=True):

        if unattended:
            self.description = f'Unattended import at {datetime.now().isoformat(timespec="milliseconds")}'
        else:
            self.description = f'Manual import at {datetime.now().isoformat(timespec="milliseconds")}'

        accounts = TextParse(self.file, unattended=unattended, strict=False, force_ascii=force_ascii)

        if self.deduplicate:
            for account in accounts:
                self._accounts.add(account)
        else:
            self._accounts = accounts


    @property
    def hash(self):

        if self._hash is None:
            self._hash = self.file.hash()
        return self._hash


    def increment(self, account):

        self.total_accounts += 1

        if account.domain:
            try:
                self.domains[account.domain] += 1
            except KeyError:
                self.domains[account.domain] = 1

        if account.password:
            for word in word_regex.findall(account.password):
                word = word.lower()
                try:
                    self.password_basewords[word] += 1
                except KeyError:
                    self.password_basewords[word] = 1

        if account.misc:
            for word in word_regex.findall(account.misc):
                word = word.lower()
                try:
                    self.misc_basewords[word] += 1
                except KeyError:
                    self.misc_basewords[word] = 1


    def top_domains(self, limit=10):

        sorted_domains = dict(sorted(self.domains.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {d: c for d,c in sorted_domains.items()}


    def top_password_basewords(self, limit=10):

        sorted_words = dict(sorted(self.password_basewords.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {w: c for w,c in sorted_words.items()}


    def top_misc_basewords(self, limit=10):

        sorted_words = dict(sorted(self.misc_basewords.items(), key=lambda x: x[1], reverse=True)[:limit])
        return {w: c for w,c in sorted_words.items()}


    @property
    def progress(self):

        try:
            return f'{self.total_accounts:,} / {bytes_to_human(self._accounts.file.size)}'
        except (NameError, AttributeError, TypeError):
            return f'{self.total_accounts:,}'


    def __iter__(self):

        for account in self._accounts:
            self.increment(account)
            yield account


    def __str__(self):

        try:
            store_dir = config['FILESTORE']['store_dir']
            filename = self.file.relative_to(store_dir)
        except (KeyError, ValueError):
            filename = self.file

        return f'{filename} (total accounts: {len(self):,})'


    def __len__(self):

        try:
            length = len(self._accounts)
        except TypeError:
            length = 0

        if length > 0:
            return length
        else:
            return self.total_accounts