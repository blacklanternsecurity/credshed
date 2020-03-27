#!/usr/bin/env python3

# by TheTechromancer

import magic
import logging
from .util import *
from ..errors import *
import subprocess as sp
from pathlib import Path

# set up logging
log = logging.getLogger('credshed.filestore.decompress')


supported_compressions = [
    # magic string      # command for decompression
    ('microsoft excel',     ['ssconvert', '-S', '{filename}', '{extract_dir}/%s.csv']),
    ('rar archive',         ['unrar', 'x', '-o+', '-p-', '{filename}', '{extract_dir}/']),
    ('tar archive',         ['tar', '--overwrite', '-xvf', '{filename}', '-C', '{extract_dir}/']),
    ('gzip compressed',     ['tar', '--overwrite', '-xvzf', '{filename}', '-C', '{extract_dir}/']),
    ('gzip compressed',     ['gunzip', '--force', '--keep', '{filename}']),
    ('bzip2 compressed',    ['tar', '--overwrite', '-xvjf', '{filename}', '-C', '{extract_dir}/']),
    ('xz compressed',       ['tar', '--overwrite', '-xvJf', '{filename}', '-C', '{extract_dir}/']),
    ('lzma compressed',     ['tar', '--overwrite', '--lzma', '-xvf', '{filename}', '-C', '{extract_dir}/']),
    ('7-zip archive',       ['7z', 'x', '-p""', '-aoa', '{filename}', '-o{extract_dir}/']),
    ('zip archive',         ['7z', 'x', '-p""', '-aoa', '{filename}', '-o{extract_dir}/']),
]


def is_compressed(filename):
    '''
    Given a filename, returns whether or not it is classified as a compressed file
    '''

    try:
        log.debug(f'Getting magic type from {filename}')
        file_type = magic.from_file(str(filename)).lower()
        log.debug(f'Magic type of {filename} is {file_type}')
    except (magic.MagicException, OSError) as e:
        log.debug(f'Error getting magic type from {filename}: {e}')
        return False

    is_supported = any([file_type.startswith(magic_type) for magic_type, cmd_list in supported_compressions])
    is_compressed = 'compressed' in file_type
    return is_supported or is_compressed



class ShellScript():

    def __init__(self):

        # make sure dependencies are installed
        for dependency in set(self.dependencies):
            self.check_if_installed(dependency)


    def mkdir(self, d):

        d = Path(d).resolve()

        log.info(f'Creating dir "{d}"')
        if d.exists():
            if not d.is_dir():
                log.error('Creation of dir "{d}" is blocked')
            else:
                log.debug(f'Dir "{d}" already exists')

        else:
            cmd_list = ['mkdir', str(d)]

            log.info(f'>> {" ".join(cmd_list)}')
            try:
                sp.run(cmd_list)
            except sp.SubprocessError as e:
                log.error(f'Error creating directory {d}: {e}')


    def check_if_installed(self, exe):

        try:
            sp.run(['hash', exe], shell=True, check=True)
        except sp.SubprocessError:
            try:
                sp.run(['hash'], shell=True, check=True)
            except sp.SubprocessError:
                raise AssertionError(f'Please install hash')
            raise AssertionError(f'Please install {exe}')


    @staticmethod
    def check_dir(d):

        d = Path(d).resolve()
        assert d.is_dir(), f'Cannot find directory "{d}"'




class Decompress(ShellScript):

    dependencies = [
        '7z',
        'tar',
        'mkdir',
        'unrar',
        'ssconvert'
    ]

    def __init__(self, filename):

        super().__init__()

        self.filename = Path(filename).resolve()
        self.extract_dir = Path(f'{self.filename}.extracted')
        try:
            log.debug(f'Getting magic type of {self.filename}')
            self.file_type = magic.from_file(str(self.filename)).lower()
            log.debug(f'Magic type of {self.filename} is {self.file_type}')
        except (magic.MagicException, OSError):
            log.error(f'Error getting magic type from {self.filename}')
            self.file_type = 'unknown'


    @property
    def is_compressed(self):

        return any([self.file_type.startswith(magic_type) for magic_type, cmd_list in supported_compressions])


    def start(self):

        decompression_success = False

        for magic_type, cmd_list in supported_compressions:
            if magic_type in self.file_type:
                log.info(f'Compression type "{magic_type}" detected in {self.filename}')
                self.mkdir(self.extract_dir)
                cmd_list = [s.format(filename=self.filename, extract_dir=self.extract_dir) for s in cmd_list]
                log.info(f'>> {" ".join(cmd_list)}')
                try:
                    sp.run(cmd_list, check=True)
                    log.info(f'Decompression successful for {self.filename}')
                    decompression_success = True
                    break
                except sp.SubprocessError as e:
                    log.error(f'Error extracting file {self.filename}: {e}')
        
                if not decompression_success:
                    try:
                        log.info(f'Decompression unsuccessful, removing directory {self.extract_dir}')
                        delete_dir(self.extract_dir)
                        continue
                    except OSError:
                        pass

        return decompression_success