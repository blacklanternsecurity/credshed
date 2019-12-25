#!/usr/bin/env python3

# by TheTechromancer

### READS CONFIG INTO config VARIABLE ###

import configparser
from .errors import *
from pathlib import Path


def read_config():

    # parse config file
    config_filename = Path(__file__).resolve().parent.parent / 'credshed.config'
    if not config_filename.is_file():
        raise CredShedConfigError('Unable to find credshed config at {}'.format(config_filename))

    config = configparser.ConfigParser()
    config.read(str(config_filename))

    return config



config = read_config()