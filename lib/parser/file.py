import os
import magic
import hashlib
import pathlib
from ..errors import *


class File(type(pathlib.Path())):
    '''
    Given a filename, yield decoded lines
    '''

    def __new__(cls, filename, *args, **kwargs):

        if type(filename) == cls:
            f = filename
        else:
            f = cls(super().__new__(cls, pathlib.Path(filename).resolve()), *args, **kwargs)

        return f


    def __init__(self, filename, force_ascii=False, parse=True):

        self._magic_type = None
        self._encoding = None
        self._size = None
        self._parse = parse
        self._force_ascii = force_ascii

        self._hashes = dict()

        super().__init__()


    @property
    def encoding(self):

        if self._encoding is None:
            self._read_magic()
        return self._encoding


    @property
    def magic_type(self):

        if self._magic_type is None:
            self._read_magic()
        return self._magic_type


    @property
    def head(self):

        try:
            with open(self, 'rb') as f:
                # read 4KB
                _head = f.read(4 * 1024)
        except OSError as e:
            raise FileReadError(e)

        return _head


    @staticmethod
    def sql_split_insert(line):
        '''
        Takes all or part of an INSERT statement and yields each SQL row separately
        '''

        sql_end = False
        row = []
        for i in range(len(line)):
            char = line[i]
            # just split on all parenthesis
            if char in ('(', ')', ';'):
                if row:
                    yield ''.join(row).replace('NULL', '')
                    row = []
                if char == ';':
                    sql_end = True
            else:
                row.append(char)

        if row:
            yield ''.join(row).replace('NULL', '')
        if sql_end:
            yield False


    def hash(self, algo='sha1', blocksize=65536):
        '''
        creates a SHA1 and MD5 hash in one go
        '''

        algo = algo.strip().lower()

        try:
            filehash = self._hashes[algo]
            log.debug(f'Hash for {self} already calculated')
            return filehash

        except KeyError:

            log.info(f'Computing hash for {self}')
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()

            try:
                with open(str(self), 'rb') as f:
                    block = f.read(blocksize)
                    while len(block) > 0:
                        sha1.update(block)
                        md5.update(block)
                        block = f.read(blocksize)

                md5_hash = md5.hexdigest()
                self._hashes['md5'] = md5_hash
                sha1_hash = sha1.hexdigest()
                self._hashes['sha1'] = sha1_hash

                log.debug(f'Successfully hashed file {self}')

            except OSError as e:
                raise FileHashError(f'Failed to hash file {self}: {e}')

        return self._hashes[algo]
    

    def _read_magic(self):

        log.debug(f'Running libmagic on {self}')

        head = self.head

        # get magic type
        if self._magic_type is None:
            self._magic_type = magic.from_buffer(head)
            log.debug(f'Magic type of {self} is {self._magic_type}')

        # get encoding
        if self._encoding is None:
            if self._force_ascii:
                self._encoding = 'ascii'
            else:
                # detect encoding with libmagic
                m = magic.Magic(mime_encoding=True)
                self._encoding = m.from_buffer(head)

            # fall back to utf-8 if encoding can't be detected
            if (not self._force_ascii) and (self._encoding == 'binary' or self._encoding.endswith('ascii')):
                self._encoding = 'utf-8'
            log.debug(f'Encoding of {self} is {self._encoding}')


    def _read_file(self):
        '''
        Tries to decode by magic type and falls back to simple binary read
        '''
        try:
            try:
                f = open(self, 'r', encoding=self.encoding)
            except LookupError:
                f = open(self, 'r', encoding='ascii')

            while 1:
                # try detected encoding
                try:
                    yield next(f).strip('\r\n')

                # if that fails, convert to hex notation
                except ValueError as e:
                    yield str(e.args[1].strip(b'\r\n'))[2:-1]
                except StopIteration:
                    break

        finally:
            f.close()


    def resolve(self):

        return self


    @property
    def size(self):
        '''
        Returns size of file in bytes
        '''

        if self._size is None:
            try:
                self._size = os.stat(str(self)).st_size
            except OSError as e:
                raise FileSizeError(f'Error getting filesize from {self}: {e}')
        return self._size



    def __iter__(self):

        assert self.is_file(), f'Cannot open {filename} as file'

        insert_into = 'INSERT INTO'
        sql_insert = False

        try:
            for line in self._read_file():

                if self._parse:
                    # handle SQL INSERT statements
                    if not sql_insert:
                        if line.startswith(insert_into):
                            log.debug(f'SQL INSERT statement detected in {self}')
                            sql_insert = True

                    if sql_insert:
                        for row in self.sql_split_insert(line):
                            if row == False:
                                log.debug(f'End of SQL INSERT statement in {self}')
                                sql_insert = False
                            else:
                                yield row
                    else:
                        yield line
                else:
                    yield line

        except OSError as e:
            log.error(f'Error opening {self}: {e}')