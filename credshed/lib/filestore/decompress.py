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
                log.info(f'Dir "{d}" already exists')

        else:
            cmd_list = ['mkdir', str(d)]

            log.debug(f'>> {" ".join(cmd_list)}')
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
        'ssconvert'
    ]

    def __init__(self, filename, filehash):

        super().__init__()

        self.filename = Path(filename).resolve()
        self.extract_dir = Path(f'{self.filename}.extracted')
        self.hash = filehash
        try:
            log.debug(f'Getting magic type of {self.filename}')
            self.file_type = magic.from_file(str(self.filename)).lower()
            log.debug(f'Magic type of {self.filename} is {self.file_type}')
        except (magic.MagicException, OSError):
            log.error(f'Error getting filetype from {self.filename}')
            self.file_type = 'unknown'

        self.supported_compressions = [
            # magic string      # command for decompression
            ('microsoft excel',  ['ssconvert', '-S', f'{self.filename}', f'{self.extract_dir}/%s.csv']),
            ('tar archive',      ['tar', '--overwrite', '-xvf', f'{self.filename}', '-C', f'{self.extract_dir}/']),
            ('gzip compressed',  ['tar', '--overwrite', '-xvzf', f'{self.filename}', '-C', f'{self.extract_dir}/']),
            ('gzip compressed',  ['gunzip', '--force', '--keep', f'{self.filename}']),
            ('bzip2 compressed', ['tar', '--overwrite', '-xvjf', f'{self.filename}', '-C', f'{self.extract_dir}/']),
            ('7-zip archive',    ['7z', 'x', '-aoa', f'{self.filename}', f'-o{self.extract_dir}/']),
            ('zip archive',      ['7z', 'x', '-aoa', f'{self.filename}', f'-o{self.extract_dir}/']),
        ]


    def decompress_if_archive(self):

        decompression_success = False

        for magic_type, cmd_list in self.supported_compressions:
            if magic_type in self.file_type:
                log.info(f'Compression type "{magic_type}" detected in {self.filename}')
                self.mkdir(self.extract_dir)
                write_metadata(self.filename, self.hash)
                log.debug(f'>> {" ".join(cmd_list)}')
                try:
                    sp.run(cmd_list, check=True)
                    log.info(f'Decompression successful, unlinking {self.filename}')
                    decompression_success = True
                    self.filename.unlink()
                    break
                except sp.SubprocessError as e:
                    log.error(f'Error extracting file {self.filename}: {e}')
        
                if not decompression_success:
                    try:
                        log.info(f'Decompression unsuccessful, removing directory {self.extract_dir}')
                        self.extract_dir.rmdir()
                        continue
                    except OSError:
                        pass

        return decompression_success