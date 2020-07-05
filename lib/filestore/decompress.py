#!/usr/bin/env python3

# by TheTechromancer

import magic
import logging
from ..errors import *
import subprocess as sp
from pathlib import Path
from .util import delete_dir, supported_compressions

# set up logging
log = logging.getLogger('credshed.filestore.decompress')


class ShellScript():

    @classmethod
    def check_dependencies(cls):

        # make sure dependencies are installed
        for dependency in set(cls.dependencies):
            cls.check_if_installed(dependency)


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


    @staticmethod
    def check_if_installed(exe):
        '''
        TODO: this doesn't work
        '''

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
        'ssconvert',
        'asdsddd'
    ]

    archive_extensions = [
        '.7z',
        '.gz',
        '.xz',
        '.lz',
        '.lzma',
        '.rar',
        '.zip',
        '.bz',
        '.bz2',
        '.bzip',
        '.bzip2',
        '.tar',
        '.xls',
        '.xlsx'
    ]

    def __init__(self, file):

        super().__init__()

        self.file = file
        self.extract_dir = Path(f'{self.file}.extracted')


    @staticmethod
    def is_compressed(file, force=False):

        extension = file.suffix.lower()
        if force or extension in Decompress.archive_extensions:
            log.debug(f'Found potential archive: {file}')
            return any([file.magic_type.lower().startswith(magic_type) for magic_type, cmd_list in supported_compressions])
        return False


    def start(self):

        decompression_success = False

        for magic_type, cmd_list in supported_compressions:
            if magic_type in self.file.magic_type.lower():
                log.info(f'Compression type "{magic_type}" detected in {self.file}')
                self.mkdir(self.extract_dir)
                cmd_list = [s.format(filename=self.file, extract_dir=self.extract_dir) for s in cmd_list]
                log.info(f'>> {" ".join(cmd_list)}')
                try:
                    sp.run(cmd_list, check=True)
                    log.info(f'Decompression successful for {self.file}')
                    decompression_success = True
                    break
                except sp.SubprocessError as e:
                    log.error(f'Error extracting file {self.file}: {e}')
        
                if not decompression_success:
                    try:
                        log.info(f'Decompression unsuccessful, removing directory {self.extract_dir}')
                        delete_dir(self.extract_dir)
                        continue
                    except OSError:
                        pass

        return decompression_success