#!/usr/bin/env python3

# by TheTechromancer


import sys
import logging
import argparse
from lib import util
from lib import logger
from time import sleep
import multiprocessing
from lib.errors import *
from pathlib import Path
from lib.credshed import *
from lib import validation
from lib.processpool import *
from datetime import datetime
from lib.filestore import util as filestore_util

# set up logging
log = logging.getLogger('credshed.cli')


class CredShedCLI(CredShed):

    def __init__(self, options):

        super().__init__()
        self.options = options

    def search(self):

        start_time = datetime.now()
        num_accounts_in_db = self.db.account_count()

        left = int(self.options.limit)

        num_results = 0
        for keyword in self.options.search:
            if self.options.limit == 0 or left > 0:
                query_type = validation.validate_query_type(keyword, self.options.query_type)
                log.info(f'Searching by {query_type}: {keyword}')
                for account in super().search(keyword, limit=left):

                    if self.options.print0:
                        sys.stdout.buffer.write(account.bytes + b'\n')
                    else:
                        print(str(account))
                    if self.options.verbose:
                        metadata = self.db.fetch_account_metadata(account)
                        if metadata:
                            print(metadata)

                    num_results += 1
                    if self.options.limit > 0:
                        if left <= 0:
                            break
                        left -= 1

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        log.info(f'Searched {num_accounts_in_db:,} accounts in {str(time_elapsed)[:-4]} seconds')
        if self.options.limit:
            total_count = 0
            for keyword in self.options.search:
                total_count += self.count(keyword)
            log.info(f'Showing {num_results:,}/{total_count:,} results')
        else:
            log.info(f'{num_results:,} results for "{" + ".join(self.options.search)}"')


    def query_stats(self):

        for keyword in self.options.search:
            stats = super().query_stats(keyword)
            log.info(stats)


    def db_stats(self):

        print(super().db_stats())


    @classmethod
    def import_file(cls, filename, options):

        if filestore_util.is_compressed(str(filename)):
            log.warning(f'Skipping compressed / encrypted file: {file}')
            return (0,0)

        try:
            return super().import_file(
                filename,
                unattended=options.unattended,
                threads=options.threads,
                show=options.show_unique,
                force=options.force_injest,
                stdout=options.stdout,
            )

        except InjestorError as e:
            log.error(f'Injestor Error: {e}')
            return (0,0)

        except KeyboardInterrupt:
            log.critical('Interrupted')
            return (0,0)


    def import_files(self):
        '''
        benchmark for full /etc import (1,500 files):
            3 process, main thread: 2:13
            3 processes: 1:27
        '''

        total_accounts = 0
        unique_accounts = 0

        # files that have at least one account (even if it's not been seen before)
        interesting_files = 0

        major_start_time = datetime.now()

        # make a list of all files (excluding compressed ones)
        filelist = list(util.recursive_file_list(self.options.injest))
        log.info(f'Importing {len(filelist):,} files')
        #sleep(2)

        # if unattended, thread like it's 1999
        if self.options.unattended:
            file_threads = 3
            self.options.threads = max(1, int(self.options.threads/3))

            with ProcessPool(file_threads, name='Import') as pool:
                for unique, total in pool.map(self.import_file, filelist, (self.options,)):
                    if total > 0:
                        interesting_files += 1
                    unique_accounts += unique
                    total_accounts += total

        # otherwise, just be normal
        else:
            for filename in filelist:
                unique, total = self.import_file(filename, self.options)
                if total > 0:
                    interesting_files += 1
                unique_accounts += unique
                total_accounts += total


        end_time = datetime.now()
        time_elapsed = (end_time - major_start_time).total_seconds()

        log.info('{:,}/{:,} unique accounts from {:,}/{:,} files in {:02d}:{:02d}:{:02d}'.format(
            unique_accounts,
            total_accounts,
            interesting_files,
            len(filelist),
            int(time_elapsed // 3600),
            int((time_elapsed % 3600) // 60),
            int(time_elapsed % 60)
        ))


    def delete_leak(self):
        
        try:

            if self.options.delete_leak:

                to_delete = {}
                for source_id in number_range(self.options.delete_leak):
                    source_info = (self.db.get_source(source_id))
                    if source_info is not None:
                        to_delete[source_id] = str(source_id) + ': ' + str(source_info)

                if to_delete:
                    errprint('\nDeleting accounts from:\n\t{}'.format('\n\t'.join(to_delete.values())), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        start_time = datetime.now()

                        log.debug(errprint('Deleting accounts from: {}'.format(', '.join(to_delete.values()))))

                        for source_id in to_delete:
                            self.delete_leak(source_id)

                        end_time = datetime.now()
                        time_elapsed = (end_time - start_time)

                        errprint('\nDeletion finished.  Time Elapsed: {}'.format(str(time_elapsed).split('.')[0]))
                        log.debug('Deletion of {} finished.  Time Elapsed: {}\n'.format(', '.join(to_delete.values()), str(time_elapsed).split('.')[0]))
                else:
                    log.warning('No valid leaks specified were specified for deletion')

            else:

                while 1:

                    assert self.db.sources.estimated_document_count() > 0, 'No more leaks in DB'
                    self.db.stats()
                    highest_source_id = self.db.highest_source_id()

                    try:
                        to_delete = [input(f'Enter ID(s) to delete [{highest_source_id}] (CTRL+C when finished): ')] or [highest_source_id]
                    except ValueError:
                        errprint('[!] Invalid entry', end='\n\n')
                        sleep(1)
                        continue

                    self.delete_leak(to_delete)


        except KeyboardInterrupt:
            errprint('\n[*] Deletion cancelled')
            sys.exit(1)



def main(options):

    try:

        try:
            credshed = CredShedCLI(options)
        except CredShedError as e:
            log.critical('{}: {}\n'.format(e.__class__.__name__, str(e)))
            sys.exit(1)

        # if we're importing stuff
        try:
            if options.injest:
                credshed.import_files()

            elif options.delete_leak is not None:
                credshed.delete_leak()

            if options.stats:
                if not options.search:
                    raise AssertionError('Please specify search query')
                credshed.query_stats()

            elif options.search:
                credshed.search()

            if options.db_stats:
                credshed.db_stats()

        except (KeyboardInterrupt, BrokenPipeError):
            log.critical('Interrupted')
            credshed.STOP = True

        except AssertionError as e:
            log.critical(e)
            sys.exit(2)

        except CredShedError as e:
            log.error('{}: {}\n'.format(e.__class__.__name__, str(e)))

        finally:
            # close mongodb connection
            credshed.db.close()

    except Exception as e:
        import traceback
        log.critical(traceback.format_exc())
        


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    # 2 <= threads <= 12
    num_cores = multiprocessing.cpu_count()
    #default_threads = max(2, min(12, (int(num_cores/1.5)+1)))
    default_threads = int(num_cores)

    parser.add_argument('search',                       nargs='*',                      help='search term(s)')
    parser.add_argument('-q', '--query-type',           default='auto',                 help='query type (email, domain, or username)')
    parser.add_argument('-i', '--injest',   type=Path,  nargs='+',                      help='import files or directories into the database')
    parser.add_argument('-f', '--force-injest',         action='store_true',            help='also injest files which have already been imported')
    parser.add_argument('-db', '--db-stats', action='store_true',                       help='show all imported leaks and DB stats')
    parser.add_argument('-t', '--stats',    action='store_true',                        help='show query statistics instead of individual accounts')
    parser.add_argument('-s', '--stdout',   action='store_true',                        help='when importing, write to stdout instead of database (null-byte delimited, use tr \'\\0\')')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from database, e.g. "1-3,5,7-9"', metavar='SOURCE_ID')
    parser.add_argument('-dd', '--deduplication',       action='store_true',            help='deduplicate accounts ahead of time (lots of memory usage on large files)')
    parser.add_argument('--threads',        type=int,   default=default_threads,        help='number of threads for import operations')
    parser.add_argument('--show-unique',                action='store_true',            help='during import, print unique accounts')
    parser.add_argument('--print0',                     action='store_true',            help='delimit search results by null byte instead of colon')
    parser.add_argument('--limit',          type=int,   default=0,                      help='limit number of results (default: unlimited)')
    parser.add_argument('-u', '--unattended',           action='store_true',            help='auto-detect import fields without user interaction')
    parser.add_argument('-v', '--verbose',              action='store_true',            help='display all available data for each account')
    parser.add_argument('--debug',                      action='store_true',            help='display debugging info')

    try:

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(0)

        logging.getLogger('credshed').setLevel(logging.INFO)

        options = parser.parse_args()

        if options.debug:
            logging.getLogger('credshed').setLevel(logging.DEBUG)
            options.verbose = True

        if options.injest and not options.unattended:
            logger.listener.start()
            main(options)

        else:
            p = multiprocessing.Process(target=main, args=(options,))
            p.start()
            logger.listener.start()

    except argparse.ArgumentError as e:
        log.error(e)
        log.error('Check your syntax')
        sys.exit(2)

    finally:
        try:
            p.join()
            logger.listener.stop()
        except:
            pass