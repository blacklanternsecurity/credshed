#!/usr/bin/env python3

# by TheTechromancer

import re
from .errors import *


# for checking if string is an email
email_regex = re.compile(r'^([A-Z0-9_\-\.\+]+)@([A-Z0-9_\-\.]+)\.([A-Z]{2,8})$', re.I)
# same thing but for raw bytes
email_regex_bytes = re.compile(rb'^([A-Z0-9_\-\.\+]+)@([A-Z0-9_\-\.]+)\.([A-Z]{2,8})$', re.I)
# for searching for email in bytes
email_regex_search_bytes = re.compile(rb'[A-Z0-9_\-\.\+]+@[A-Z0-9_\-\.]+\.[A-Z]{2,8}', re.I)
# less-strict version
fuzzy_email_regex = re.compile(r'^(.+)@(.+)\.(.+)')
# same thing but for raw bytes
fuzzy_email_regex_bytes = re.compile(rb'^(.+)@(.+)\.(.+)')
# domain
domain_regex = re.compile(r'^([A-Z0-9_\-\.]*)\.([A-Z]{2,8})$', re.I)


def is_domain(domain):

    if domain_regex.match(domain):
        return True
    return False


def is_email(email):

    # abort if value is too long
    if len(email) > 128:
        return False

    try:
        if email_regex.match(email):
            return True
    except TypeError:
        if email_regex_bytes.match(email):
            return True

    return False


def is_fuzzy_email(email):

    if len(email) > 128:
        return False

    try:
        if fuzzy_email_regex.match(email):
            return True
    except TypeError:
        if fuzzy_email_regex_bytes.match(email):
            return True

    return False



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
