#!/usr/bin/env python3

# by TheTechromancer

import re
from .errors import *
from base64 import b64decode
from binascii import Error as Base64Error

# for checking if string is an email
email_regex = re.compile(r'^([A-Z0-9][A-Z0-9_\-\.\+]{,100})@([A-Z0-9][A-Z0-9_\-\.]{,100})\.([A-Z]{2,8})$', re.I)
# for searching for email in string
email_regex_search = re.compile(r'[A-Z0-9][A-Z0-9_\-\.\+]{,100}@[A-Z0-9][A-Z0-9_\-\.]{,100}\.[A-Z]{2,8}', re.I)
# less-strict version
fuzzy_email_regex = re.compile(r'^(.+)@(.+)\.(.+)')
# domain
domain_regex = re.compile(r'^([A-Z0-9_\-\.]*)\.([A-Z]{2,8})$', re.I)
# for finding base words in password
word_regex = re.compile(r'[a-z]{1}[a-z13450@$]{1,18}[a-z]{1}', re.I)
# for checking for hashed passwords
# matches 227/240 (95%) of hashcat's example passwords

hash_regexes = [
    # {smd5}a5/yTL/u$VfvgyHx1xUlXZYBocQpQY0
    r'{[a-z0-9-]{3,15}}[a-z0-9/\.\$+]{20,1000}={0,2}',
    # $P$984478476IagS59wHZvyQMArzfx58u.
    r'\${0,1}[a-z0-9_-]{1,16}\$[a-z0-9/\.\*\$+=]{20,1000}',
    # AK1AAECAwQFBgcICRARNGqgeC3is8gv2xWWRony9NJnDgE=
    r'[a-z0-9/+]{20,1000}={1,2}',
    # 8743b52063cd84097a65d1633f5c74f5
    r'[a-f0-9]{1}[a-f0-9:]{30,1000}[a-f0-9]{1}',
]

hash_regexes_str   = [re.compile(r, re.I) for r in hash_regexes]

# valid characters for email addresses
email_charset = 'abcdefghijklmnopqrstuvwxyz0123456789-_.+@'


def is_domain(domain):

    if domain_regex.match(domain):
        return True
    return False


def is_email(email):

    # abort if value is too long
    if len(email) >= 256:
        return False

    if email_regex.match(email):
        return True

    return False


def is_fuzzy_email(email):

    if len(email) > 128:
        return False

    if fuzzy_email_regex.match(email):
        return True


    return False


def is_hash(s):

    # go in reverse
    for i in range(len(hash_regexes)-1, -1, -1):
        if hash_regexes_str[i].match(s):
            return True
    return False


def find_hashes(s):

    for hash_regex in hash_regexes_str:
        for match in hash_regex.findall(s):
            yield match


def strip_hashes(s):

    for hash_regex in hash_regexes_str:
        s = re.sub(hash_regex, '', s)

    return s


def validate_query_type(query, query_type='auto'):
    '''
    returns valid query type, autodetects if needed
    '''

    query_type = query_type.strip().lower()

    if query_type == 'email' and is_email(query):
        return query_type

    if query_type == 'domain' and is_domain(query):
        return query_type

    # try to auto-detect query type
    if is_email(query):
        return 'email'
    elif is_domain(query):
        return 'domain'

    raise CredShedValidationError(f'Invalid query: "{query}"')
