#!/usr/bin/env python3.7

# by TheTechromancer

'''
TODO:
    - when importing, prompt user for confirmation (with first / last 10 files and total count)
'''

import sys
import argparse
from lib.core import *
from pathlib import Path
from datetime import datetime
from multiprocessing import cpu_count



class CredShedCLI(CredShed):

    def __init__(self, output='__db__', unattended=False, deduplication=False, threads=2):

        # if we're outputting to a file instead of the DB
        if not str(output) == '__db__':
            # validate output destination
            self.output = self.output.resolve()
            assert not self.output.is_dir(), 'Creation of {} is blocked'.format(self.output)
            if self.output.exists():
                errprint('[!] Overwriting {} - CTRL+C to cancel'.format(self.output))
                sleep(5)

        super().__init__(unattended=unattended, deduplication=deduplication, threads=threads)


    def _search(self, query):

        start_time = datetime.now()
        num_accounts_in_db = self.db.account_count()

        num_results = 0
        for result in self.search(query):
            print(result)
            num_results += 1

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        errprint('\n[+] Searched {:,} accounts in {} seconds'.format(num_accounts_in_db, str(time_elapsed)[:-4]))
        errprint('[+] {:,} results for "{}"'.format(num_results, '|'.join(query)))


    def _stats(self):

        print(self.stats())



def main(options):

    try:
        cred_shed = CredShedCLI(output=options.out, unattended=options.unattended, deduplication=options.deduplication, threads=options.threads)
    except CredShedError as e:
        stderr.write('[!] {}\n'.format(str(e)))
        sys.exit(1)

    # if we're importing stuff
    try:
        if options.add:
            cred_shed.import_files(options.add)

        elif options.delete_leak is not None:
            cred_shed.delete_leaks(options.delete_leak)

        if options.search:
            cred_shed._search(options.search)

        if options.stats:
            cred_shed._stats()

    except CredShedError as e:
        sys.stderr.write('[!] {}'.format(str(e)))

    except KeyboardInterrupt:
        sys.stderr.write('[!] CredShed Interrupted\n')
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
    parser.add_argument('-a', '--add',      type=Path,  nargs='+',                      help='add file(s) to DB')
    parser.add_argument('-t', '--stats',    action='store_true',                        help='show db stats')
    parser.add_argument('-o', '--out',      type=Path,  default='__db__',               help='write output to file instead of DB')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from DB, e.g. "1-3,5,7-9"', metavar='SOURCE_ID')
    parser.add_argument('-dd', '--deduplication',       action='store_true',            help='deduplicate accounts ahead of time (may eat memory)')
    parser.add_argument('-p', '--search-passwords',     action='store_true',            help='search by password')
    parser.add_argument('-m', '--search-description',   action='store_true',            help='search by description / misc')
    parser.add_argument('--threads',        type=int,   default=default_threads,        help='number of threads for import operations')
    parser.add_argument('-u', '--unattended',           action='store_true',            help='auto-detect import fields without user interaction')

    try:

        if len(sys.argv) < 2:
            parser.print_help()
            exit(0)

        options = parser.parse_args()
        #print(options.delete_leak)
        #exit(1)

        main(options)

    except argparse.ArgumentError as e:
        errprint('\n\n[!] {}\n[!] Check your syntax'.format(str(e)))
        exit(2)

    #except (KeyboardInterrupt, BrokenPipeError):
    #    errprint('\n\n[!] Interrupted')
    #    exit(1)

    except AssertionError as e:
        errprint('\n\n[!] {}'.format(str(e)))

    finally:
        try:
            outfile.close()
        except:
            pass