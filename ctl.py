#!/usr/bin/env python3.7

'''
TODO:
    - if target of "-a" is a directory, parse all files contained therein
        - don't forget to prompt user for confirmation (with first / last 10 and count)
'''

import os
import sys
import argparse
from lib.db import DB
from lib.leak import *
from time import sleep
from pathlib import Path
from lib.quickparse import *
from datetime import datetime
from multiprocessing import cpu_count



def get_leak_dirs(path):
    '''
    takes directory
    walks tree, stops walking and yields directory when it finds a file
    '''

    path = Path(path).resolve()
    try:
        dir_name, dir_list, file_list = next(os.walk(path))
        if file_list:
            #print(' - ', str(path))
            yield path
        else:
            for d in dir_list:
                for p in get_leak_dirs(path / d):
                    yield p
    except StopIteration:
        pass


def get_leak_files(path):
    '''
    takes directory
    yields:
    [
        (leak_dir, leak_file)
        ...
    ]

    each directory and file represent a full path when concatenated
        e.g.:
            leak_dir / leak_file
    '''

    leak_dirs = {}

    for d in get_leak_dirs(path):
        leak_files = []
        for dir_name, dir_list, file_list in os.walk(d):
            for file in file_list:
                yield (d.parent, (Path(dir_name) / file).relative_to(d.parent))




def number_range(s):

    n_array = set()

    for a in s:
        for r in a.split(','):
            try:
                if '-' in r:
                    start, end = [int(i) for i in r.split('-')[:2]]
                    n_array = n_array.union(set(list(range(start, end+1))))
                else:
                    n_array.add(int(r))

            except (IndexError, ValueError):
                errprint('[!] Error parsing source ID "{}"'.format(a))
                continue

    return n_array




def main(options):

    db = DB()

    if not str(options.out) == '__db__':
        # validate output destination
        options.out = options.out.resolve()
        assert not options.out.is_dir(), 'Creation of {} is blocked'.format(str(options.out))
        if options.out.exists():
            errprint('[!] Overwriting {} - CTRL+C to cancel'.format(str(options.out)))
            sleep(3)
        with open(options.out, 'w') as f:
            f.write('')


    if options.add:
        errors = []
        to_add = set()
        for file in options.add:
            if file.is_file():
                to_add.add((file, None))
            elif file.is_dir():
                to_add.update(set(get_leak_files(file)))
            else:
                continue


        for l in to_add:

            if l[1] is None:
                leak_file = l[0]
                leak_friendly_name = file.name
            else:
                leak_dir, leak_friendly_name = l
                leak_file = leak_dir / leak_friendly_name

            #print(leak_file, leak_friendly_name)

            try:

                q = QuickParse(file=leak_file, source_name=leak_friendly_name, unattended=options.unattended)

            except QuickParseError as e:
                e = '[!] {}'.format(str(e))
                errprint('\n' + e)
                errors.append(e)
                continue

            except KeyboardInterrupt:
                errprint('\n[*] Skipping {}'.format(str(file)))
                continue

            leak = Leak(q.source_name, q.source_hashtype, q.source_misc)
            # make sure source doesn't already exist
            if db.sources.find_one(leak.source.document(misc=False)) is not None:
                errprint('[!] Source already exists')
                continue
                #assert False, 'Source already exists'

            if options.no_deduplication:
                leak.accounts = q.__iter__()

            else:
                account_counter = 0
                errprint('[+] Deduplicating accounts')
                for account in q:
                    #errprint(str(account))
                    try:
                        leak.add_account(account)
                    except ValueError:
                        continue
                    account_counter += 1
                    if account_counter % 1000 == 0:
                        errprint('\r[+] {:,} '.format(account_counter), end='')
                errprint('\r[+] {:,}'.format(account_counter))

            if options.out.name == '__db__':

                #print('\nAdding:\n{}'.format(str(leak)))

                db.add_leak(leak, num_threads=options.threads)

            else:
                errprint('\n[+] Writing batch to {}\n'.format(str(options.out)))
                with open(options.out, 'wb+') as f:
                    for account in leak:
                        #errprint(str(account))
                        f.write(account.to_bytes() + b'\n')
                #leak.dump()

        if options.unattended and errors:
            errprint('Errors encountered:\n\t', end='')
            errprint('\n\t'.join(errors))


    elif options.delete_leak is not None:

        try:

            if options.delete_leak:

                to_delete = {}
                for source_id in number_range(options.delete_leak):
                    source_info = (db.get_source(source_id))
                    if source_info is not None:
                        to_delete[source_id] = str(source_id) + ': ' + str(source_info)

                if to_delete:
                    errprint('\nDeleting all entries from:\n\t{}'.format('\n\t'.join(to_delete.values())), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        for source_id in to_delete:
                            start_time = datetime.now()
                            db.remove_leak(source_id)
                            end_time = datetime.now()
                            time_elapsed = (end_time - start_time)
                else:
                    errprint('[!] No valid leaks specified were specified for deletion')

            else:

                while True:

                    assert db.sources.estimated_document_count() > 0, 'No more leaks in DB'
                    most_recent_source_id = db.show_stats()

                    try:
                        to_delete = int(input('Enter ID to delete [{}] (CTRL+C when finished): '.format(most_recent_source_id)) or most_recent_source_id)
                    except ValueError:
                        errprint('[!] Invalid entry', end='\n\n')
                        sleep(1)
                        continue

                    errprint('\nDeleting all entries from:\n\t{}: {}'.format(to_delete, str(db.get_source(to_delete))), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        start_time = datetime.now()
                        db.remove_leak(to_delete)
                        end_time = datetime.now()
                        time_elapsed = (end_time - start_time)
                        errprint('\n[+] Time Elapsed: {}\n'.format(str(time_elapsed).split('.')[0]))

        except KeyboardInterrupt:
            errprint('\n[*] Deletion cancelled')


    if options.search:

        start_time = datetime.now()
        num_results = 0

        for result in db.find(options.search):
            num_results += 1
            #print('{}:{}@{}:{}:{}'.format(result['username'], result['email'], result['domain'], result['password'], result['misc']))
            print(result)

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        errprint('\n[+] Total Results: {:,}'.format(num_results))
        errprint('[+] Time Elapsed: {}\n'.format(str(time_elapsed)[:-4]))


    if options.stats:

        db.show_stats(accounts=True, counters=True, sources=True, db=True)




if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    default_threads = cpu_count()

    parser.add_argument('search',                       nargs='*',                      help='search term(s)')
    parser.add_argument('-a', '--add',      type=Path,  nargs='+',                      help='add file(s) to DB')
    parser.add_argument('-t', '--stats',    action='store_true',                        help='show db stats')
    parser.add_argument('-o', '--out',      type=Path,  default='__db__',               help='write output to file instead of DB')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from DB, e.g. "1-3,5,7-9"')
    parser.add_argument('-n', '--no-deduplication',     action='store_true',            help='don\'t deduplicate accounts (saves on memory usage)')
    parser.add_argument('-p', '--search-passwords',     action='store_true',            help='search by password')
    parser.add_argument('-m', '--search-description',   action='store_true',            help='search by description / misc')
    parser.add_argument('--threads',        type=int,   default=default_threads,        help='number of threads for import operations')
    parser.add_argument('--unattended',                 action='store_true',            help='auto-detect import fields without user interaction')

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

    except (KeyboardInterrupt, BrokenPipeError):
        errprint('\n\n[!] Interrupted')
        exit(1)

    except AssertionError as e:
        errprint('\n\n[!] {}'.format(str(e)))

    finally:
        try:
            outfile.close()
        except:
            pass