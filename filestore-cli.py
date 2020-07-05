#!/usr/bin/env python3

# by TheTechromancer

import sys
import logging
import argparse
from lib import logger
from time import sleep
import multiprocessing
from lib.errors import *
from pathlib import Path
from lib.filestore import *


# set up logging
log = logging.getLogger('credshed.filestore.cli')



def main(options):

    try:

        f = Filestore(store_dir=options.dir)

        if options.consolidate:
            log.warning('--consolidate COMBINES SMALLER FILES THEN DELETES THE ORIGINAL')
            log.warning(f'THIS WILL DELETE ALL FILES SMALLER THAN 2MB IN {f.dir}')
            log.warning(f'Press CTRL+C within 5 seconds to cancel.')
            #sleep(5)
            f.consolidate_files(dry_run=False)

        if options.extract:
            f.extract_files(
                threads=options.threads,
                delete=options.delete,
                force=options.force_extract
            )

    except KeyboardInterrupt:
        log.critical('Interrupted')

    except Exception as e:
        import traceback
        log.critical(traceback.format_exc())



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('dir',                  type=Path,              help='override filestore dir in credshed.config')
    parser.add_argument('-e', '--extract',      action='store_true',    help='decompress all supported archives')
    parser.add_argument('--force-extract',      action='store_true',    help='check magic type on all files even if the file extension doesn\'t suggest it\'s compressed')
    parser.add_argument('-c', '--consolidate',  action='store_true',    help='combine smaller files by extension (careful with this)')
    parser.add_argument('-t', '--threads',      type=int, default=4,    help='number of files to decompress concurrently')
    parser.add_argument('--delete',             action='store_true',    help='delete archives after successful decompression (original filename and hash are still saved)')
    parser.add_argument('-d', '--debug',        action='store_true',    help='display debugging info')

    try:

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(0)

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