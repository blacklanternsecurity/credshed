#!/usr/bin/env python3.7

'''
TODO:
    - prompt user for confirmation (with first / last 10 files and total count)
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




def number_range(s):
    '''
    takes array of strings and tries to convert into an array of ints
    '''

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




class CredShed():

    def __init__(self, output='__db__', unattended=False, deduplication=False):

        self.db = DB()
        self.output = Path(output)
        self.unattended = unattended
        self.deduplication = deduplication

        self.errors = []

        # if we're outputting to a file instead of the DB
        if not str(output) == '__db__':
            # validate output destination
            self.output = self.output.resolve()
            assert not self.output.is_dir(), 'Creation of {} is blocked'.format(self.output)
            if self.output.exists():
                errprint('[!] Overwriting {} - CTRL+C to cancel'.format(self.output))
                sleep(5)
            with open(str(self.output), 'w') as f:
                f.write('')



    def search(self, query):
        '''
        query = search string
        '''

        start_time = datetime.now()
        num_results = 0

        for result in self.db.find(str(query)):
            num_results += 1
            #print('{}:{}@{}:{}:{}'.format(result['username'], result['email'], result['domain'], result['password'], result['misc']))
            print(result)

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        errprint('\n[+] Total Results: {:,}'.format(num_results))
        errprint('[+] Time Elapsed: {}\n'.format(str(time_elapsed)[:-4]))



    def stats(self):

        self.db.show_stats(accounts=True, counters=True, sources=True, db=True)



    def import_files(self, files):
        '''
        takes a single file or directory, or a list of files/directories to import
        '''

        # make sure "files" is an iterable
        if type(files) == str or type(files) == Path:
            files = [files]

        to_add = set()
        # get file listing for any directories
        for file in files:
            if file.is_file():
                to_add.add((file, None))
            elif file.is_dir():
                to_add.update(set(self._get_leak_files(file)))
            else:
                continue


        # if we're importing a lot of files, parallelize
        if len(to_add) > 1 and self.unattended and str(self.output) == '__db__':
            file_threads = 4
            options.threads = max(2, min(12, int(options.threads / file_threads)+1))
            errprint('[+] {:,} files detected, adding in parallel ({} threads + {} per file)'.format(len(to_add), file_threads, options.threads))

            futures = []

            #with concurrent.futures.ThreadPoolExecutor(max_workers=file_threads) as file_thread_executor:

            file_thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=file_threads)
            #with concurrent.futures.ProcessPoolExecutor(max_workers=file_threads) as file_thread_executor:
            #with concurrent.futures.ThreadPoolExecutor(max_workers=file_threads) as file_thread_executor:
            #for result in file_thread_executor.map(lambda a: add_leak(*a), [(l, options) for l in to_add]):
            #    #errprint('[+] Job finished')
            #    errprint(result)
            for l in to_add:
                futures.append(file_thread_executor.submit(self._add_by_file, l))

            '''
            try:
                file_thread_executor.shutdown(wait=True)
            except KeyboardInterrupt:
                errprint('[!] Shutting down threads forcefully')
                for future in futures:
                    future.cancel()
            '''

            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                print('\n>> {:,} FILES COMPLETED <<\n'.format(completed))

            file_thread_executor.shutdown(wait=False)

        else:
            for l in to_add:
                self._add_by_file(l)


        if options.unattended and self.errors:
            errprint('Errors encountered:\n\t', end='')
            errprint('\n\t'.join(self.errors))



    def delete_leaks(self, leak_ids=[]):

        try:

            if leak_ids:

                to_delete = {}
                for source_id in number_range(leak_ids):
                    source_info = (self.db.get_source(source_id))
                    if source_info is not None:
                        to_delete[source_id] = str(source_id) + ': ' + str(source_info)

                if to_delete:
                    errprint('\nDeleting all entries from:\n\t{}'.format('\n\t'.join(to_delete.values())), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        start_time = datetime.now()
                        with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
                            for source_id in to_delete:
                                executor.submit(self.db.remove_leak, source_id)

                        end_time = datetime.now()
                        time_elapsed = (end_time - start_time)                                
                else:
                    errprint('[!] No valid leaks specified were specified for deletion')

            else:

                while True:

                    assert self.db.sources.estimated_document_count() > 0, 'No more leaks in DB'
                    most_recent_source_id = self.db.show_stats()

                    try:
                        to_delete = int(input('Enter ID to delete [{}] (CTRL+C when finished): '.format(most_recent_source_id)) or most_recent_source_id)
                    except ValueError:
                        errprint('[!] Invalid entry', end='\n\n')
                        sleep(1)
                        continue

                    errprint('\nDeleting all entries from:\n\t{}: {}'.format(to_delete, str(self.db.get_source(to_delete))), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        start_time = datetime.now()
                        self.db.remove_leak(to_delete)
                        end_time = datetime.now()
                        time_elapsed = (end_time - start_time)
                        errprint('\n[+] Time Elapsed: {}\n'.format(str(time_elapsed).split('.')[0]))

        except KeyboardInterrupt:
            errprint('\n[*] Deletion cancelled')




    def _add_by_file(self, dir_and_file):
        '''
        takes iterable of directories and files in the format:
        [
            (leak_dir, leak_file)
            ...
        ]
        '''

        #errprint('[+] Initializing db for {}'.format(dir_and_file))
        db = DB()
        #errprint('[{}] Instantiated DB'.format(dir_and_file))

        try:

            # if leak_file is None, assume leak_dir is just a standalone file
            if dir_and_file[1] is None:
                leak_file = dir_and_file[0]
                leak_friendly_name = leak_file.name
            else:
                leak_dir, leak_friendly_name = dir_and_file
                leak_file = leak_dir / leak_friendly_name

            #print(leak_file, leak_friendly_name)

            try:

                #errprint('[+] Initializing QuickParse object for {}'.format(dir_and_file))
                q = QuickParse(file=leak_file, source_name=leak_friendly_name, unattended=self.unattended, strict=True)
                #errprint('[+] Finished initializing QuickParse object for {}'.format(dir_and_file))

            except QuickParseError as e:
                e = '[!] {}'.format(str(e))
                e2 = '[*] Falling back to non-strict mode'
                errprint(e)
                errprint(e2)
                q = QuickParse(file=leak_file, source_name=leak_friendly_name, unattended=self.unattended, strict=False)
                #self.errors.append(e)
                #self.errors.append(e2)

            except KeyboardInterrupt:
                errprint('\n[*] Skipping {}'.format(str(leak_file)))
                return

            leak = Leak(q.source_name, q.source_hashtype, q.source_misc)

            # see if source already exists
            source_already_in_db = db.sources.find_one(leak.source.document(misc=False, date=False))
            if source_already_in_db:
                if not self.unattended:
                    answer = input('Source ID {} ({}) already exists, merge? (Y/n)'.format(source_already_in_db['_id'], source_already_in_db['name'])) or 'y'
                    if not answer.lower().startswith('y'):
                        errprint('[*] Skipping existing source ID {} ({})'.format(source_already_in_db['_id'], source_already_in_db['name']))
                        return

            if not self.deduplication:
                # override set with generator
                leak.accounts = q.__iter__()

            else:
                account_counter = 0
                errprint('[+] Deduplicating accounts')
                for account in q:
                    #errprint(str(account))
                    #try:
                    leak.add_account(account)
                    #except ValueError:
                    #    continue
                    account_counter += 1
                    if account_counter % 1000 == 0:
                        errprint('\r[+] {:,} '.format(account_counter), end='')
                errprint('\r[+] {:,}'.format(account_counter))


            if self.output.name == '__db__':

                #print('\nAdding:\n{}'.format(str(leak)))
                #file_thread_executor.submit(db.add_leak, leak, num_threads=options.threads)
                #errprint('[{}] Calling db.add_leak()'.format(dir_and_file))
                db.add_leak(leak, num_threads=options.threads)
                #errprint('[{}] Finished calling db.add_leak()'.format(dir_and_file))

            else:
                errprint('\n[+] Writing batch to {}\n'.format(str(self.output)))
                # open file in append mode because we may be parsing more than one file
                with open(str(self.output), 'wb+') as f:
                    for account in leak:
                        #errprint(str(account))
                        f.write(account.to_bytes() + b'\n')
                #leak.dump()

        finally:
            errprint('[+] Finished adding {}'.format(leak_file))
            db.close()


    def _get_leak_dirs(self, path):
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
                    for p in self._get_leak_dirs(path / d):
                        yield p
        except StopIteration:
            pass


    def _get_leak_files(self, path):
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

        for d in self._get_leak_dirs(path):
            leak_files = []
            for dir_name, dir_list, file_list in os.walk(d):
                for file in file_list:
                    yield (d.parent, (Path(dir_name) / file).relative_to(d.parent))






def main(options):

    cred_shed = CredShed(output=options.out, unattended=options.unattended, deduplication=options.deduplication)


    # if we're importing stuff
    try:
        if options.add:
            cred_shed.import_files(options.add)

        elif options.delete_leak is not None:
            cred_shed.delete_leaks(options.delete_leak)

        if options.search:
            cred_shed.search(options.search)

        if options.stats:
            cred_shed.stats()

    finally:
        # close mongodb connection
        cred_shed.db.close()
        




if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    # 2 <= threads <= 12
    default_threads = max(2, min(12, (int(cpu_count()/1.5)+1)))

    parser.add_argument('search',                       nargs='*',                      help='search term(s)')
    parser.add_argument('-a', '--add',      type=Path,  nargs='+',                      help='add file(s) to DB')
    parser.add_argument('-t', '--stats',    action='store_true',                        help='show db stats')
    parser.add_argument('-o', '--out',      type=Path,  default='__db__',               help='write output to file instead of DB')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from DB, e.g. "1-3,5,7-9"')
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