#!/usr/bin/env python3

# by TheTechromancer

import logging
from copy import copy
from pathlib import Path
from multiprocessing import Queue
from logging.handlers import QueueHandler, QueueListener


### PRETTY COLORS ###

class ColoredFormatter(logging.Formatter):

    color_mapping = {
        'DEBUG':    69, # blue
        'INFO':     118, # green
        'WARNING':  208, # orange
        'ERROR':    196, # red
        'CRITICAL': 196, # red
    }

    char_mapping = {
        'DEBUG':    '*',
        'INFO':     '+',
        'WARNING':  '-',
        'ERROR':    '!',
        'CRITICAL': '!!!',
    }

    prefix = '\033[1;38;5;'
    suffix = '\033[0m'

    def __init__(self, pattern):

        super().__init__(pattern)


    def format(self, record):

        colored_record = copy(record)
        levelname = colored_record.levelname
        levelchar = self.char_mapping.get(levelname, '+')
        seq = self.color_mapping.get(levelname, 15) # default white
        colored_levelname = f'{self.prefix}{seq}m[{levelchar}]{self.suffix}'
        colored_record.levelname = colored_levelname

        return logging.Formatter.format(self, colored_record)



### LOG TO STDERR ###

console = logging.StreamHandler()
# tell the handler to use this format
console.setFormatter(ColoredFormatter('%(levelname)s %(message)s'))


### LOG TO FILE ###

root_logger = logging.getLogger('credshed')

# set up a multiprocessing queue to allow easy logging from subprocesses
log_queue = Queue()
listener = QueueListener(log_queue, console)
log_sender = QueueHandler(log_queue)
root_logger.handlers = [log_sender]
#root_logger.handlers = [console]

filename = 'credshed.log'
log_filename = str(Path('/var/log/credshed') / filename)

# use logging to log logging logs
log = logging.getLogger('credshed.logger')

try:
    file_handler = logging.FileHandler(log_filename)
except (PermissionError, FileNotFoundError):
    log.warning(f'Unable to create log file at {log_filename}, logging to current directory')
    file_handler = logging.FileHandler(filename)

log_format = '%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s'
file_handler.setFormatter(logging.Formatter(log_format))
root_logger.addHandler(file_handler)
root_logger.setLevel(logging.DEBUG)