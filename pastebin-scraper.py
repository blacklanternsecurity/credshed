#!/usr/bin/env python3.7

# by TheTechromancer
# Original Author: Jordan Wright
# Modified by: Moez @ CriticalStart

import sys
import logging
import argparse
from credshed import *
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

    pastebin = Pastebin(options.loop_delay, options.scrape_limit)
    pastebin.monitor()



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    default_loop_delay = 60
    default_scrape_limit = 100

    parser.add_argument('-d', '--loop-delay',   type=int,   default=default_loop_delay,     help=f'seconds between API queries (default {default_loop_delay})')
    parser.add_argument('-s', '--scrape-limit', type=int,   default=default_scrape_limit,   help=f'max pastes to scrape at once (default {default_scrape_limit})')
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