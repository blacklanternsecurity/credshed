#!/usr/bin/env python3.7

import re
import sys
import base64
import hashlib
from pathlib import Path
from datetime import datetime


class AccountCreationError(Exception):
    pass


def errprint(*s, end='\n'):

    sys.stderr.write(''.join([str(i) for i in s]) + end)
    sys.stderr.flush()


class Account():

    # cut down on memory usage by not using a dictionary
    __slots__ = ['email', 'username', 'password', 'misc']

    email_regex = re.compile(r'^([a-zA-Z0-9_\-\.\+]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,8})$')
    email_regex_bytes = re.compile(rb'^([a-zA-Z0-9_\-\.\+]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,8})$')

    def __init__(self, email=b'', username=b'', password=b'', _hash=b'', misc=b''):

        self.email = email.strip().lower()
        self.username = username.strip()
        if _hash and not password:
            self.password = _hash.strip()
        else:
            self.password = password
        self.misc = misc.strip()

        if email:
            if not self.email_regex_bytes.match(email):
                if not username:
                    self.username = email
                else:
                    errprint('\n[*] Invalid email: {}'.format(email))
                self.email = b''

        elif self.is_email(username) and not self.email:
            self.email = username.lower()
            self.username = b''

        if not ( (self.email or self.username) and (self.password or self.misc) ):
            raise AccountCreationError('need either username or email and either a password or misc description')

        for v in [self.email, self.username, self.password]:
            if len(v) >= 255:
                raise AccountCreationError('Value {} is too long'.format(str(v)[2:-1]))


    def document(self, id_only=False):

        doc = dict()

        try:
            doc['_id'] = self.to_object_id()
            if not id_only:
                if self.email:
                    doc['email'], doc['domain'] = self.email.decode(encoding='utf-8').split('@')[:2]
                    doc['domain'] = doc['domain'][::-1]
                if self.username: doc['username'] = self.username.decode(encoding='utf-8')
                if self.password: doc['password'] = self.password.decode(encoding='utf-8')
                if self.misc: doc['misc'] = self.misc.decode(encoding='utf-8')

        except UnicodeDecodeError as e:
            errprint('\n[!] Error decoding {}'.format(str(self.to_bytes())))
            return None
        except ValueError:
            errprint('\n[!] Error formatting {}'.format(str(self.to_bytes())))

        return doc


    @classmethod
    def from_document(self, document):

        try:
            email = (document['email'] + '@' + document['domain'][::-1]).encode(encoding='utf-8')
        except KeyError:
            email = b''
        except UnicodeEncodeError:
            email = str(email)[2:-1] + b'@' + str(domain[::-1])[2:-1]
        username = self._if_key_exists(document, 'username')
        password = self._if_key_exists(document, 'password')
        misc = self._if_key_exists(document, 'misc')
        return Account(email, username, password, misc)


    @classmethod
    def is_email(self, email):

        try:
            if self.email_regex.match(email):
                return True
        except TypeError:
            if self.email_regex_bytes.match(email):
                return True

        return False


    @staticmethod
    def _if_key_exists(d, k):

        try:
            return d[k].encode(encoding='utf-8')
        except KeyError:
            return b''
        except UnicodeEncodeError:
            return str(d[k])[2:-1]


    def to_bytes(self, delimiter=b'\x00'):

        return delimiter.join([self.email, self.username, self.password, self.misc])


    def to_object_id(self):
        '''
        poor man's domain index
        if email exists, then first 6 characters are a hash of the domain
        '''

        if self.email:
            #return hashlib.sha1(b'.'.join(self.email.split(b'@')[1].split(b'.')[-2:])).digest()[:5] + hashlib.sha1(self.to_bytes()).digest()[:7]
            domain_chunk = base64.b64encode(hashlib.sha1(b'.'.join(self.email.split(b'@')[1].split(b'.')[-2:])).digest()).decode()[:6]
            main_chunk = base64.b64encode(hashlib.sha1(self.to_bytes()).digest()).decode()[:10]
            return domain_chunk + main_chunk
        else:
            return base64.b64encode(hashlib.sha1(self.to_bytes()).digest())[:16].decode()


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

        try:
            return ':'.join((self.email.decode(), self.username.decode(), self.password.decode(), self.misc.decode()))
        except UnicodeDecodeError:
            return str(self.to_bytes(delimiter=b':'))[2:-1]



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
            sys.stdout.buffer.write(account.to_bytes() + b'\n')


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