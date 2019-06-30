#!/usr/bin/env python3.7

# by TheTechromancer

'''
TODO:
    - logging
    - mongodb auth
    - allow imports to primary / metadata servers independently
        - try to connect to metadata server and if it doesn't respond, EYTONY NO PROOOBLEMMMM
    - when importing, prompt user for confirmation (with first / last 10 files and total count)
    - performance benchmarks (4x 500GB Samsung SSDs in LVM RAID 0):
        - 4 shards:
            - >> 3,666 files completed in 4 days, 2:33:34 <<
            - [+] Searched 1,021,786,928 accounts in 0:00:00.06 seconds
        - 10 shards:
            - >> 4,549/29,551 (15.4%) files completed in 3 days, 7:17:19 <<
            - [+] Searched 1,174,146,654 accounts in 0:00:00.07 seconds
'''

import sys
import argparse
from credshed import *
from pathlib import Path
from datetime import datetime
from multiprocessing import cpu_count



class CredShedCLI(CredShed):

    def __init__(self, output='__db__', unattended=False, metadata=True, metadata_only=False, deduplication=False, threads=2):

        # if we're outputting to a file instead of the DB
        if not str(output) == '__db__':
            # validate output destination
            self.output = self.output.resolve()
            assert not self.output.is_dir(), 'Creation of {} is blocked'.format(self.output)
            if self.output.exists():
                errprint('[!] Overwriting {} - CTRL+C to cancel'.format(self.output))
                sleep(5)

        super().__init__(unattended=unattended, metadata=metadata, metadata_only=metadata_only, deduplication=deduplication, threads=threads)

        if not self.db.use_metadata:
            if metadata_only:
                raise CredShedMetadataError('"metadata_only" option specified but none available')
            else:
                errprint('[*] Continuing without metadata support')
                self.metadata=False


    def _search(self, query, query_type, verbose=False):

        start_time = datetime.now()
        num_accounts_in_db = self.db.account_count()

        num_results = 0
        for account in self.search(query, query_type=query_type, verbose=verbose):
            print(str(account))
            if verbose:
                metadata = self.db.fetch_account_metadata(account)
                if metadata:
                    print(metadata)
            num_results += 1

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        errprint('\n[+] Searched {:,} accounts in {} seconds'.format(num_accounts_in_db, str(time_elapsed)[:-4]))
        errprint('[+] {:,} results for "{}"'.format(num_results, '|'.join(query)))


    def _stats(self):

        print(self.stats())



def main(options):

    try:
        cred_shed = CredShedCLI(output=options.out, unattended=options.unattended, \
            metadata=(not options.no_metadata), metadata_only=options.metadata_only, \
            deduplication=options.deduplication, threads=options.threads)
    except CredShedError as e:
        errprint('[!] {}\n'.format(str(e)))
        sys.exit(1)

    options.query_type = options.query_type.strip().lower()
    assert options.query_type in ['auto', 'email', 'domain', 'username'], 'Invalid query type: {}'.format(str(options.query_type))

    # if we're importing stuff
    try:
        if options.add:
            cred_shed.import_files(options.add)

        elif options.delete_leak is not None:
            cred_shed.delete_leaks(options.delete_leak)

        if options.search:
            for keyword in options.search:

                # auto-detect query type
                if options.query_type == 'auto':
                    if Account.is_email(keyword):
                        options.query_type = 'email'
                        errprint('[+] Searching by email')
                    elif re.compile(r'^([a-zA-Z0-9_\-\.]*)\.([a-zA-Z]{2,8})$').match(keyword):
                        options.query_type = 'domain'
                        errprint('[+] Searching by domain')
                    else:
                        raise CredShedError('Failed to auto-detect query type, please specify with --query-type')
                        return
                        # options.query_type = 'username'
                        # errprint('[+] Searching by username')

                cred_shed._search(options.search, query_type=options.query_type, verbose=options.verbose)

        if options.stats:
            cred_shed._stats()

    except CredShedError as e:
        errprint('[!] {}'.format(str(e)))

    except KeyboardInterrupt:
        cred_shed.STOP = True
        errprint('\n[!] Stopping CLI\n')
        return

    finally:
        # close mongodb connection
        cred_shed.db.close()
        


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    # 2 <= threads <= 12
    num_cores = cpu_count()
    #default_threads = max(2, min(12, (int(num_cores/1.5)+1)))
    default_threads = int(num_cores)

    parser.add_argument('search',                       nargs='*',                      help='search term(s)')
    parser.add_argument('-q', '--query-type',           default='auto',                 help='query type (email, domain, or username)')
    parser.add_argument('-a', '--add',      type=Path,  nargs='+',                      help='add file(s) to DB')
    parser.add_argument('-t', '--stats',    action='store_true',                        help='show db stats')
    parser.add_argument('-o', '--out',      type=Path,  default='__db__',               help='write output to file instead of DB')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from DB, e.g. "1-3,5,7-9"', metavar='SOURCE_ID')
    parser.add_argument('-dd', '--deduplication',       action='store_true',            help='deduplicate accounts ahead of time (may eat memory)')
    parser.add_argument('-p', '--search-passwords',     action='store_true',            help='search by password')
    parser.add_argument('-m', '--search-description',   action='store_true',            help='search by description / misc')
    parser.add_argument('--threads',        type=int,   default=default_threads,        help='number of threads for import operations')
    parser.add_argument('-u', '--unattended',           action='store_true',            help='auto-detect import fields without user interaction')
    parser.add_argument('--no-metadata',                action='store_true',            help='disable metadata database')
    parser.add_argument('--metadata-only',              action='store_true',            help='when importing, only import metadata')
    parser.add_argument('-v', '--verbose',              action='store_true',            help='display all available data for each account')

    try:

        if len(sys.argv) < 2:
            parser.print_help()
            exit(0)

        options = parser.parse_args()

        assert not (options.no_metadata and options.metadata_only), "Conflicting options: --no-metadata and --only-metadata"
        #print(options.delete_leak)
        #exit(1)

        main(options)

    except AssertionError as e:
        errprint('\n\n[!] {}\n'.format(str(e)))
        exit(2)

    except argparse.ArgumentError as e:
        errprint('\n\n[!] {}\n[!] Check your syntax'.format(str(e)))
        exit(2)

    #except (KeyboardInterrupt, BrokenPipeError):
    #    errprint('\n\n[!] Interrupted')
    #    exit(1)

    except AssertionError as e:
        errprint('\n\n[!] {}'.format(str(e)))

    except (KeyboardInterrupt, BrokenPipeError):
        errprint('\n\n[!] Interrupted')

    finally:
        try:
            outfile.close()
        except:
            pass