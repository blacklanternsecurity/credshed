#!/usr/bin/env python3.7

# by TheTechromancer

import re
import sys
import base64
import hashlib
from .util import *
from .errors import *
from pathlib import Path
from datetime import datetime



class Account():

    # cut down on memory usage by not using a dictionary
    __slots__ = ['email', 'username', 'password', 'misc']

    valid_email_chars = b'abcdefghijklmnopqrstuvwxyz0123456789-_.+@'
    # for checking if string is an email
    email_regex = re.compile(r'^([a-zA-Z0-9_\-\.\+]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,8})$')
    # same thing but for raw bytes
    email_regex_bytes = re.compile(rb'^([a-zA-Z0-9_\-\.\+]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,8})$')
    # for searching for email in string
    email_regex_search_bytes = re.compile(rb'([a-zA-Z0-9_\-\.\+]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,8})')
    # less-strict version
    fuzzy_email_regex = re.compile(r'^(.+)@(.+)\.(.+)')
    # same thing but for raw bytes
    fuzzy_email_regex_bytes = re.compile(rb'^(.+)@(.+)\.(.+)')

    # max length for email, username, and password
    max_length_1 = 128
    # max length for hash, misc
    max_length_2 = 256

    def __init__(self, email=b'', username=b'', password=b'', _hash=b'', misc=b''):

        # abort if values are too long
        # saves the regexes from hogging CPU
        #for v in [email, username, password]:
        #    if len(v) >= self.max_length_1:
        #        raise AccountCreationError('Value too long: {}'.format(str(v)[2:-1][:64]))
        #for vi in [_hash, misc]:
        #    if len(v) >= self.max_length_2:
        #        raise AccountCreationError('Hash or desc. too long: {}'.format(str(v)[2:-1][:64]))

        self.email = b''
        email = email.strip().lower()
        for i in range(len(email)):
            c = email[i:i+1]
            if c in self.valid_email_chars:
                self.email += c
        # remove whitespace, single-quotes, and backslashes
        self.username = username.strip().translate(None, b"'\\")
        self.misc = misc.strip()

        if not self.email:
            if self.is_email(self.username):
                # errprint('\n[+] Username "{}" is an email'.format(str(self.username)))
                self.email = self.username.lower()
                self.username = b''

        else:
            if not self.is_email(self.email):
                #errprint('[*] Invalid email: {}'.format(self.email))
                if not self.username:
                    # errprint('\n[+] Changing to username')
                    self.email, self.username = self.username, self.email

        if _hash and not password:
            self.password = _hash.strip()
        else:
            self.password = password

        # keeping an email by itself is sometimes useful
        # if not strictly for OSINT purposes, at least knowing which leaks it was a part of
        # allows searching for additional information in the raw dump
        if not (self.email or (self.username and (self.password or self.misc))):
            # print(email, username, password, _hash, misc)
            raise AccountCreationError('Not enough information to create account:\n{}'.format(str(self)[:64]))

        # truncate values if longer than max length
        self.email = clean_encoding(self.email)[-self.max_length_1:]
        self.username = clean_encoding(self.username)[:self.max_length_1]
        self.password = clean_encoding(self.password)[:self.max_length_1]
        self.misc = clean_encoding(self.misc)[-self.max_length_2:]


    @property
    def _id(self):

        return self.to_object_id()


    @property
    def document(self, id_only=False):
        '''
        note: values must be truncated again here because they may become longer when decoded
        '''

        doc = dict()

        try:
            doc['_id'] = self.to_object_id()
            if not id_only:
                if self.email:
                    doc['email'] = decode(self.split_email[0])
                if self.username:
                    doc['username'] = decode(self.username)
                if self.password:
                    doc['password'] = decode(self.password)
                if self.misc:
                    doc['misc'] = decode(self.misc)
        except ValueError:
            raise AccountCreationError('[!] Error formatting {}'.format(str(self.bytes)[:64]))

        return doc



    @property
    def split_email(self):

        try:
            email, domain = self.email.split(b'@')[:2]
            return [email, domain]
        except ValueError:
            return [self.email, b'']



    @property
    def domain(self):
        domain = self.email.split(b'@')[-1]



    @classmethod
    def from_document(self, document):

        try:
            email = (document['email'] + '@' + document['_id'].split('|')[0][::-1]).encode(encoding='utf-8')
        except KeyError:
            email = b''
        except UnicodeEncodeError:
            email = str(email)[2:-1] + b'@' + str(domain[::-1])[2:-1]
        except ValueError:
            raise AccountCreationError('Unable to determine domain from _id {}'.format(str(document['_id'])))
        username = self._if_key_exists(document, 'username')
        password = self._if_key_exists(document, 'password')
        misc = self._if_key_exists(document, 'misc')
        return Account(email=email, username=username, password=password, misc=misc)


    @classmethod
    def is_email(self, email):

        # abort if value is too long
        if len(email) > self.max_length_1:
            return False

        try:
            if self.email_regex.match(email):
                return True
        except TypeError:
            if self.email_regex_bytes.match(email):
                return True

        return False


    @classmethod
    def is_fuzzy_email(self, email):

        if len(email) > 128:
            return False

        try:
            if self.fuzzy_email_regex.match(email):
                return True
        except TypeError:
            if self.fuzzy_email_regex_bytes.match(email):
                return True

        return False



    @staticmethod
    def _if_key_exists(d, k):

        try:
            return encode(d[k])
        except KeyError:
            return b''


    @property
    def bytes(self, delimiter=b'\x00'):

        return delimiter.join([self.email, self.username, self.password, self.misc])


    def to_object_id(self):
        '''
        hacky compound domain-->email index
        first 6 bytes of _id after the domain are a hash of the email
        '''

        if self.email:
            # _id begins with reversed domain
            email, domain = self.split_email
            domain_chunk = decode(domain[::-1])
            email_hash = decode(base64.b64encode(hashlib.sha256(email).digest()[:6]))
            account_hash = email_hash + decode(base64.b64encode(hashlib.sha256(self.bytes).digest()[:6]))
        else:
            account_hash = decode(base64.b64encode(hashlib.sha256(self.bytes).digest()[:12]))
            domain_chunk = ''

        return '|'.join([domain_chunk, account_hash])


    def __repr__(self):

        if self.username:
            return self.username
        else:
            return self.email


    def __eq__(self, other):

        if hash(self) == hash(other):
            return True
        else:
            return False


    def __hash__(self):

        #return hash(self.email + self.username + self.password + self.misc)
        return hash(self.email + self.username + self.password + self.misc)


    def __str__(self):

        return ':'.join([decode(b) for b in [self.email, self.username, self.password, self.misc]])



class Source():

    def __init__(self, name, hashtype='', misc='', date=None):

        self.name       = name
        self.hashtype   = hashtype.upper()
        self.misc       = misc
        if date is None:
            self.date   = datetime.now()
        elif not type(date) == datetime:
            raise TypeError('invalid date format, must be datetime(), not {} / {}'.format(type(date), str(date)))
        else:
            self.date   = date


    def document(self, misc=True, date=False):

        doc = dict()

        doc['name'] = self.name
        doc['hashtype'] = self.hashtype
        if misc:
            doc['misc'] = self.misc
        if date:
            doc['date'] = self.date

        return doc


    def __eq__(self, other):

        return (self.name == other.name) and (self.hashtype == other.hashtype)


    def __str__(self):

        return '{}, {}{}'.format(self.name, self.hashtype, (' ({})'.format(self.misc) if self.misc else ''))




class AccountMetadata():

    def __init__(self, sources):

        self.sources = sources


    def __str__(self):

        s = ''
        s += '\n'.join([' |- {}'.format(str(source)) for source in self.sources])
        return s


    def __len__(self):

        return len(self.sources)




class Leak():

    def __init__(self, source_name='unknown', source_hashtype='', source_misc='', file=None):

        self.source         = Source(source_name, source_hashtype, source_misc)
        self.accounts       = set()

        if file:
            self.read(file)


    def add_account(self, *args, **kwargs):
        '''
        email='', username='', password='', misc=''
        '''

        try:
            if type(args[0]) == Account:
                self.accounts.add(args[0])
                return
        except IndexError:
            pass

        self.accounts.add(Account(*args, **kwargs))


    def dump(self, folder='cleaned', maximum=None):
        '''
        dump format is email:username:password:misc
        with null bytes in place of colons
        '''

        '''

        folder = Path(folder).resolve()
        folder.mkdir(mode=0o750, exist_ok=True)
        assert folder.is_dir(), '{} is not a folder.'.format(folder)

        file = folder / '{}-{}.txt'.format(self.source.name, self.source.hashtype)
        assert not file.exists(), '{} already exists.'.format(file)

        errprint('[+] Dumping to {}'.format(file))

        c = 0
        with open(file, 'wb') as f:
            for account in self.accounts:
                f.write(account.to_bytes() + b'\n')
                if maximum:
                    if c >= maximum:
                        break
                if c % 1000 == 0:
                    errprint('\r[+] {:,}'.format(c), end='')
                c += 1
        errprint('')
        '''
        for account in self.accounts:
            sys.stdout.buffer.write(account.bytes + b'\n')


    def read(self, file):

        q = QuickParse(file)
        self.source.name = q.source_name
        self.source.hashtype = q.source_hashtype
        for account in q:
            self.add_account(account)


    def __iter__(self):

        for account in self.accounts:
            yield account


    def __str__(self):

        s  = '{}:\n'.format(self.source.name)
        s += '  unique accounts: {:,}'.format(len(self))

        return s


    def __len__(self):

        return len(self.accounts)