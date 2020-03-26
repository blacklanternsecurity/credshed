#!/usr/bin/env python3

# by TheTechromancer

import sys
import logging
import argparse
from lib import logger
import multiprocessing
from lib.errors import *
from pathlib import Path
from lib.filestore import *


# set up logging
log = logging.getLogger('credshed.filestore.cli')



def main(options):

    f = Filestore(store_dir=options.dir)

    if options.extract:
        f.extract_files()



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('-e', '--extract',      action='store_true',    help='decompress all supported archives')
    parser.add_argument('--dir',                type=Path,              help='override filestore dir in credshed.config')
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

        p = multiprocessing.Process(target=main, args=(options,))
        p.start()
        logger.listener.start()

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

    finally:
        try:
            p.join()
            logger.listener.stop()
        except:
            pass