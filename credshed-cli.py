#!/usr/bin/env python3

# by TheTechromancer


import sys
import logging
import argparse
from credshed import *
from time import sleep
from pathlib import Path
from datetime import datetime
from credshed.lib import logger
from multiprocessing import cpu_count

# set up logging
log = logging.getLogger('credshed.cli')


class CredShedCLI(CredShed):

    def __init__(self, options):

        super().__init__(stdout=options.stdout)

        self.options = options

        if not self.db.meta_client:
            log.warning('Continuing without metadata support')


    def search(self, query, query_type):

        start_time = datetime.now()
        num_accounts_in_db = self.db.account_count()

        num_results = 0
        for account in super().search(query, query_type=query_type, limit=self.options.limit):
            if self.options.print0:
                sys.stdout.buffer.write(account.bytes + b'\n')
            else:
                print(str(account))
            if self.options.verbose:
                metadata = self.db.fetch_account_metadata(account)
                if metadata:
                    print(metadata)
            num_results += 1

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        log.info(f'Searched {num_accounts_in_db:,} accounts in {str(time_elapsed)[:-4]} seconds')
        log.info(f'{num_results:,} results for "{query}"')


    def stats(self):

        print(super().stats())


    def import_files(self):

        total_unique_accounts = 0

        # files that have at least one account (even if it's not unique)
        interesting_files = 0

        major_start_time = datetime.now()

        filelist = list(util.recursive_file_list(self.options.injest))
        log.info(f'Importing {len(filelist):,} files')
        #sleep(2)

        try:
            for filename in filelist:

                log.info(f'Parsing file {filename}')

                minor_start_time = datetime.now()

                try:
                    unique_accounts, total_accounts = self.import_file(
                        filename,
                        unattended=self.options.unattended,
                        threads=self.options.threads,
                        show=options.show_unique
                    )
                    if total_accounts > 0:
                        interesting_files += 1
                    if unique_accounts > 0:
                        total_unique_accounts += unique_accounts

                    end_time = datetime.now()
                    time_elapsed = (end_time - minor_start_time).total_seconds()

                    if total_accounts > 0:
                        log.info('{:,}/{:,} ({:.2f}%) new accounts in "{}"  Time elapsed: {:02d}:{:02d}:{:02d}'.format(
                            unique_accounts,
                            total_accounts,
                            ((unique_accounts / total_accounts) * 100), 
                            filename,
                            # // == floor division
                            int(time_elapsed // 3600),
                            int((time_elapsed % 3600) // 60),
                            int(time_elapsed % 60)
                        ))

                except InjestorError as e:
                    log.error(f'Injestor Error: {e}')
                    continue

        except KeyboardInterrupt:
            sys.stderr.write('\n')
            log.warning('Import operations cancelled')
            pass

        end_time = datetime.now()
        time_elapsed = (end_time - major_start_time).total_seconds()

        log.info('{:,} unique accounts from {:,} files in {:02d}:{:02d}:{:02d}'.format(
            total_unique_accounts,
            interesting_files,
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
        credshed = CredShedCLI(options)
    except CredShedError as e:
        log.critical('{}: {}\n'.format(e.__class__.__name__, str(e)))
        sys.exit(1)

    options.query_type = options.query_type.strip().lower()
    assert options.query_type in ['auto', 'email', 'domain', 'username'], f'Invalid query type: {options.query_type}'

    # if we're importing stuff
    try:
        if options.injest:

            credshed.import_files()

        elif options.delete_leak is not None:
            credshed.delete_leak()

        if options.search:

            keyword = options.search[0]

            # auto-detect query type
            if options.query_type == 'auto':
                if Account.is_email(keyword):
                    query_type = 'email'
                    log.debug('Searching by email: "{}"'.format(keyword))
                elif re.compile(r'^([A-Z0-9_\-\.]*)\.([A-Z]{2,8})$', re.I).match(keyword):
                    query_type = 'domain'
                    log.debug('Searching by domain: "{}"'.format(keyword))
                else:
                    raise CredShedError('Failed to auto-detect query type, please specify with --query-type')
                    return
                    # options.query_type = 'username'
                    # errprint('[+] Searching by username')

            credshed.search(options.search, query_type)

        if options.stats:
            credshed.stats()

    except CredShedError as e:
        log.error('{}: {}\n'.format(e.__class__.__name__, str(e)))

    except KeyboardInterrupt:
        credshed.STOP = True
        errprint('\n[!] Stopping CLI, please wait for threads to finish\n')
        return

    finally:
        # close mongodb connection
        credshed.db.close()
        


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    # 2 <= threads <= 12
    num_cores = cpu_count()
    #default_threads = max(2, min(12, (int(num_cores/1.5)+1)))
    default_threads = int(num_cores)

    parser.add_argument('search',                       nargs='*',                      help='search term(s)')
    parser.add_argument('-q', '--query-type',           default='auto',                 help='query type (email, domain, or username)')
    parser.add_argument('-i', '--injest',   type=Path,  nargs='+',                      help='import files or directories into the database')
    parser.add_argument('-t', '--stats',    action='store_true',                        help='show all imported leaks and DB stats')
    parser.add_argument('-s', '--stdout',   action='store_true',                        help='write output to stdout instead of database (null-byte delimited, use tr \'\\0\')')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from database, e.g. "1-3,5,7-9"', metavar='SOURCE_ID')
    parser.add_argument('-dd', '--deduplication',       action='store_true',            help='deduplicate accounts ahead of time (lots of memory usage on large files)')
    parser.add_argument('--threads',        type=int,   default=default_threads,        help='number of threads for import operations')
    parser.add_argument('--show-unique',                action='store_true',            help='during import, print unique accounts')
    parser.add_argument('--print0',                     action='store_true',            help='delimit by null byte instead of colon')
    parser.add_argument('--limit',                      type=int,                       help='limit number of results (default: unlimited)')
    parser.add_argument('-u', '--unattended',           action='store_true',            help='auto-detect import fields without user interaction')
    parser.add_argument('-v', '--verbose',              action='store_true',            help='display all available data for each account')
    parser.add_argument('--debug',                      action='store_true',            help='display debugging info')

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

        main(options)

    except AssertionError as e:
        errprint(f'\n\n[!] {e}\n')
        sys.exit(2)

    except argparse.ArgumentError as e:
        errprint(f'\n\n[!] {e}\n[!] Check your syntax')
        sys.exit(2)

    except (KeyboardInterrupt, BrokenPipeError):
        errprint('\n\n[!] Interrupted')

    finally:
        try:
            outfile.close()
        except:
            pass
