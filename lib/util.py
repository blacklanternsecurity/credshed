#!/usr/bin/env python3

# by TheTechromancer


def clean_encoding(s):

    if type(s) == bytes:
        return decode(s).encode(encoding='utf-8')
    elif type(s) == str:
        return decode(s.encode(encoding='utf-8'))
    raise ValueError('Incorrect type passed to clean_encoding()')


def encode(s):

	try:
		return s.encode(encoding='utf-8')
	except UnicodeEncodeError:
		return ''


def decode(b):

    try:
        return b.decode(encoding='utf-8')
    except UnicodeDecodeError:
        return str(b)[2:-1]