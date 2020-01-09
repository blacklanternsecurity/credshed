#!/usr/bin/env python3

# by TheTechromancer

import sys
import logging
import argparse
from pathlib import Path
from credshed.lib import logger
from credshed.lib.errors import *
from credshed.lib.filestore import *


# set up logging
log = logging.getLogger('credshed.filestore.cli')



def main(options):

    f = Filestore()

    if options.extract:
        f.extract_files()

    # rebuild the index if it's empty or if requested
    if not f.index or options.update_index or options.rebuild_index:
        if options.rebuild_index:
            log.warning('Clearing index in preparation for rebuild')
        else:
            f.index.read()
        f.update_index()
        f.index.write()

    if options.list_index:
        print(json.dumps(f.index.json, indent=4, sort_keys=True))



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('-l', '--list-index',   action='store_true',    help='list filestore index')
    parser.add_argument('-u', '--update-index', action='store_true',    help='update filestore index')
    parser.add_argument('-r', '--rebuild-index',action='store_true',    help='discard & rebuild filestore index (time-consuming)')
    parser.add_argument('-e', '--extract',      action='store_true',    help='decompress all supported archives')
    # parser.add_argument('-dd', '--deduplicate', action='store_true',    help='replace duplicate files with symlinks to original')
    parser.add_argument('-d', '--debug',        action='store_true',    help='display debugging info')

    try:

        #if len(sys.argv) < 2:
        #    parser.print_help()
        #    sys.exit(0)

        options = parser.parse_args()

        if options.debug:
            logging.getLogger('credshed').setLevel(logging.DEBUG)
            options.verbose = True
        else:
            logging.getLogger('credshed').setLevel(logging.INFO)

        main(options)

    except AssertionError as e:
        log.error(f'AssertionError {e}')
        sys.exit(2)

    except CredShedError as e:
        log.error(f'CredShedError {e}')
        sys.exit(2)

    except argparse.ArgumentError as e:
        log.error(f'{e} - Check your syntax')
        sys.exit(2)

    except (KeyboardInterrupt, BrokenPipeError):
        log.error(f'Interrupted')