#!/usr/bin/env python3

# by TheTechromancer

import sys
import logging
import argparse
from lib import logger
from lib.errors import *
from pathlib import Path
from lib.scraper import *
from lib.credshed import *

# set up logging
log = logging.getLogger('credshed.scraper.cli')


def main(options):

    try:
        cred_shed = CredShed(unattended=True, metadata=(not options.no_metadata),
            metadata_only=options.metadata_only, deduplication=True, threads=1)
    except CredShedError as e:
        log.critical('{}: {}\n'.format(e.__class__.__name__, str(e)))
        sys.exit(1)

    pastebin = Pastebin(cred_shed, options.loop_delay, options.scrape_limit, options.save_dir, (not options.dont_save))
    if options.report or options.email_report:
        report = PasteBinReport(pastebin, days=options.report_days, limit=options.report_limit)
        if options.report:
            for line in report.report():
                print(line)
        if options.email_report:
            report.email(to=options.email_report)
    else:
        pastebin.monitor()



if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    default_loop_delay = 60
    default_scrape_limit = 100
    default_report_days = 30
    default_report_limit = 20
    default_save_dir = Path.cwd()

    parser.add_argument('-d', '--loop-delay',   type=int,   default=default_loop_delay,     help=f'seconds between API queries (default {default_loop_delay})')
    parser.add_argument('-s', '--scrape-limit', type=int,   default=default_scrape_limit,   help=f'max pastes to scrape at once (default {default_scrape_limit})')
    parser.add_argument('--save-dir',                   type=Path,                          help=f'save pastes as files here (default {default_save_dir})')
    parser.add_argument('--dont-save',                  action='store_true',                help="don't write pastes to file")
    parser.add_argument('--no-metadata',                action='store_true',                help='disable metadata database')
    parser.add_argument('--metadata-only',              action='store_true',                help='when importing, only import metadata')
    parser.add_argument('--report',                     action='store_true',                help='summarize recent pastes')
    parser.add_argument('--email-report',       type=str,   nargs='+',                      help='send report to this email address')
    parser.add_argument('--report-days',        type=int,   default=default_report_days,    help=f'how may days to go back (default {default_report_days})')
    parser.add_argument('--report-limit',       type=int,   default=default_report_limit,   help=f'limit report size (default {default_report_limit})')
    parser.add_argument('--debug',                      action='store_true',                help='display debugging info')

    try:

        options = parser.parse_args()

        assert not (options.no_metadata and options.metadata_only), "Conflicting options: --no-metadata and --only-metadata"

        if options.debug:
            logging.getLogger('credshed').setLevel(logging.DEBUG)
        else:
            logging.getLogger('credshed').setLevel(logging.INFO)

        p = multiprocessing.Process(target=main, args=(options,))
        p.start()
        logger.listener.start()

    except AssertionError as e:
        errprint('\n\n[!] {}\n'.format(str(e)))
        exit(2)

    except argparse.ArgumentError as e:
        errprint('\n\n[!] {}\n[!] Check your syntax'.format(str(e)))
        exit(2)

    except KeyboardInterrupt:
        errprint('\n\n[!] Interrupted')

    finally:
        try:
            p.join()
            logger.listener.stop()
        except:
            pass