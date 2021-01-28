# by TheTechromancer

import base64
import hashlib
from .util import *
from .errors import *
from . import validation



class Account():

    # cut down on memory usage by not using a dictionary
    __slots__ = ['_id', '_email', 'domain', 'username', 'password', 'hashes', 'misc', 'sources']

    # max length for email, domain, username, and password
    max_length_1 = 127
    # max length for hash, misc
    max_length_2 = 1023

    # translation table to strip bad characters from username
    strip_from_username = str.maketrans('', '', "'\\")

    def __init__(self, email='', username='', password='', hashes=[], misc='', sources=[]):

        # validate types
        if type(hashes) == str:
            hashes = [hashes]
        if type(sources) in (str, int):
            sources = [int(s)]
        else:
            sources = [int(s) for s in sources]

        # sanitize
        email    = validation.clean_utf(email)
        username = validation.clean_utf(username)
        password = validation.clean_utf(password)
        hashes   = [validation.clean_utf(h) for h in hashes]
        misc     = validation.clean_utf(misc)

        # initialize variables
        self._id = ''
        self._email = ''
        self.username = ''
        self.password = ''
        self.misc = ''
        self.hashes = []
        self.sources = sources

        self.set_email(email)

        # sanitize username
        self.username = username.strip().translate(self.strip_from_username)[:self.max_length_1]

        # truncate values to max length
        self.misc = misc[:self.max_length_2]
        self.password = password[:self.max_length_1]
        for h in hashes:
            if h not in self.hashes:
                self.hashes.append(h[:self.max_length_2])

        # if username is an email address, do the needful
        if not self._email:
            if validation.is_email(self.username):
                self.set_email(self.username)
                self.username = ''

        # if password is hashed, put it in hash field
        if self.password:
            if validation.is_hash(self.password):
                self.hashes.append(self.password)
                self.password = ''

        # if the password is super long, put it in misc
        if not self.misc and len(self.password) >= self.max_length_1:
            self.password, self.misc = '', self.password

        # keeping an email by itself is sometimes useful
        # if not strictly for OSINT purposes, at least knowing which leaks it was a part of
        # allows searching for additional information in the raw dump
        if not (self._email or (self.username and (self.password or self.misc or self.hashes))):
            raise AccountCreationError(f'Not enough information to create account:\n{str(self)[:64]}')


    @property
    def document(self, id_only=False):
        '''
        Returns dictionary in database format
        '''

        doc = dict()

        try:
            doc['_id'] = self.id
            if not id_only:
                if self._email:
                    doc['e'] = self._email
                if self.username:
                    doc['u'] = self.username
                if self.password:
                    doc['p'] = self.password
                if self.hashes:
                    doc['h'] = self.hashes
                if self.misc:
                    doc['m'] = self.misc
        except ValueError:
            raise AccountCreationError(f'[!] Error formatting {str(self.bytes)[:64]}')

        return doc


    @property
    def json(self):
        '''
        Returns dictionary in human-friendly format
        '''
        j = dict()
        j['e'] = self.email
        j['u'] = self.username
        j['p'] = self.password
        j['h'] = self.hashes
        j['m'] = self.misc
        j['s'] = self.sources
        return j
    


    def set_email(self, email):

        self._email = ''
        new_email = validation.clean_email(email)[-self.max_length_1:]
        if not validation.is_email(new_email):
            raise AccountCreationError(f'Invalid email: {new_email}')

        self._email, self.domain = new_email.split('@', 1)
        self._email, self.domain = self.handle_special_email_cases(self._email, self.domain)



    @staticmethod
    def handle_special_email_cases(email, domain):
        '''
        Handles special gmail email address tricks, etc.
        '''

        # handle gmail
        if domain in ['gmail.com', 'googlemail.com']:
            return (email.replace('.', '').split('+')[0], domain)
        else:
            return (email, domain)



    @classmethod
    def from_document(cls, document):

        _email = document.get('e')
        domain = document.get('_id').split('|')[0]
        if _email and domain:
            email = _email + '@' + domain[::-1]
        else:
            email = ''
        username = document.get('u', '')
        password = document.get('p', '')
        hashes = document.get('h', [])
        misc = document.get('m', '')
        sources = document.get('s', [])
        return cls(email=email, username=username, password=password, hashes=hashes, misc=misc, sources=sources)


    @property
    def bytes(self, delimiter=b'\x00'):

        return delimiter.join(
            x.encode('utf-8', errors='ignore') for x in 
            [self.email, self.username, self.password, self.formatted_hashes, self.misc]
        )


    @property
    def id(self):
        '''
        hacky compound domain-->email index
        first 6 bytes of _id after the domain are a hash of the email
        '''

        if not self._id:

            if self._email:
                # _id begins with reversed domain
                domain_chunk = self.domain[::-1]
                email_hash = base64.b64encode(hashlib.sha1(self._email.encode()).digest()[:6]).decode()
                account_hash = email_hash + base64.b64encode(hashlib.sha1(self.bytes).digest()[:6]).decode()
            else:
                account_hash = base64.b64encode(hashlib.sha1(self.bytes).digest()[:12]).decode()
                domain_chunk = ''

            self._id = '|'.join([domain_chunk, account_hash])

        return self._id

        '''
        # sha1 is used for speed, collisions are *very* unlikely in datasets of this size

        if not self._id:
            self._id = base64.b64encode(hashlib.sha256(self.bytes).digest())[:20].decode()
        return self._id
        '''


    @property
    def formatted_hashes(self):

        hashes = list(set(self.hashes))
        hashes.sort(key=lambda x: len(x))
        return '|'.join(hashes)


    @property
    def email(self):

        if self._email and self.domain:
            return self._email + '@' + self.domain
        else:
            return ''


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

        return hash(self.bytes)


    def __str__(self):

        return ':'.join([self.email, self.username, self.password, self.formatted_hashes, self.misc])


    def __iter__(self):

        for k,v in self.document.items():
            yield (k,v)