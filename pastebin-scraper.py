#!/usr/bin/env python3.7

# by TheTechromancer
# Original Author: Jordan Wright
# Modified by: Moez @ CriticalStart

import sys
import logging
import argparse
from credshed import *
from pathlib import Path
from credshed.lib.pastebin import *

# set up logging
log = logging.getLogger('credshed.pastebin')
log.setLevel(logging.DEBUG)

# log INFO and up to stderr
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
# set a format which is simpler for console use
formatter = logging.Formatter('[%(levelname)s] %(message)s')
# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('credshed').addHandler(console)


def main(options):

    try:
        cred_shed = CredShed(unattended=True, metadata=(not options.no_metadata),
            metadata_only=options.metadata_only, deduplication=True, threads=1)
    except CredShedError as e:
        log.critical('{}: {}\n'.format(e.__class__.__name__, str(e)))
        sys.exit(1)

    pastebin = Pastebin(cred_shed, options.loop_delay, options.scrape_limit, options.save_dir, (not options.dont_save))
    pastebin.monitor()



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    default_loop_delay = 60
    default_scrape_limit = 100
    default_save_dir = Path.cwd()

    parser.add_argument('-d', '--loop-delay',   type=int,   default=default_loop_delay,     help=f'seconds between API queries (default {default_loop_delay})')
    parser.add_argument('-s', '--scrape-limit', type=int,   default=default_scrape_limit,   help=f'max pastes to scrape at once (default {default_scrape_limit})')
    parser.add_argument('--save-dir',                   type=Path,                          help=f'save pastes as files here (default {default_save_dir})')
    parser.add_argument('--dont-save',                  action='store_true',                help="don't write pastes to file")
    parser.add_argument('--no-metadata',                action='store_true',                help='disable metadata database')
    parser.add_argument('--metadata-only',              action='store_true',                help='when importing, only import metadata')

    try:

        options = parser.parse_args()

        assert not (options.no_metadata and options.metadata_only), "Conflicting options: --no-metadata and --only-metadata"

        main(options)

    except AssertionError as e:
        errprint('\n\n[!] {}\n'.format(str(e)))
        exit(2)

    except argparse.ArgumentError as e:
        errprint('\n\n[!] {}\n[!] Check your syntax'.format(str(e)))
        exit(2)

    except AssertionError as e:
        errprint('\n\n[!] {}'.format(str(e)))

    except KeyboardInterrupt:
        errprint('\n\n[!] Interrupted')