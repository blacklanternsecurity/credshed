#!/usr/bin/env python3.7

# by TheTechromancer

# to fix:
# threads seem to stay alive after finishing
'''
    $ pstree | grep pyth                                                                                                                                                     
            |-python3.7---2*[{python3.7}]                                                                                                                                                         
                           |      |-python3.7-+-2*[head]                                                                                                                                          
                           |      |           |-17*[python3.7---6*[{python3.7}]]                                                                                                                  
                           |      |           |-5*[python3.7---7*[{python3.7}]]
                           |      |           `-284*[{python3.7}]
    $ pstree | grep pyth
            |-python3.7---2*[{python3.7}]                                       
                           |      |-python3.7-+-16*[python3.7---6*[{python3.7}]]
                           |      |           |-8*[python3.7---7*[{python3.7}]]
                           |      |           `-385*[{python3.7}]
    $ pstree | grep pyth
            |-python3.7---2*[{python3.7}]
                           |      |-python3.7-+-21*[python3.7---6*[{python3.7}]]
                           |      |           |-3*[python3.7---7*[{python3.7}]]
                           |      |           `-427*[{python3.7}]
    $ pstree | grep pyth
            |-python3.7---2*[{python3.7}]
                           |      `-python3.7-+-16*[python3.7---5*[{python3.7}]]
                           |                  |-6*[python3.7---7*[{python3.7}]]
                           |                  |-2*[python3.7]
                           |                  `-6508*[{python3.7}]



============================================================                                                                                                                                                       
 /mnt/n0/leak/cleaning/bigDB/Shopping Collection/22.txt                                                                                                                                                            
============================================================                                                                                                                                                       
Source name:         bigDB/Shopping Collection/22.txt                                                                                                                                                              
Source hashtype:                                                                                                                                                                                                   
Source description:  Unattended import at 2019-03-15T20:07:22.724                                                                                                                                                  
[+] Finished adding /mnt/n0/leak/cleaning/bigDB/Shopping Collection/22.txt                                                                                                                                         
                                                                                                                                                                                                                   
>> 3,628 FILES COMPLETED <<                                                                                                                                                                                        
                                                                                                                                                                                                                   
============================================================                                                                                                                                                       
 /mnt/n0/leak/cleaning/bigDB/Database Collection/XLSX Base Collection/База Kupivip.ru - 4 200 000 контактов/База Kupivip.ru - 4 200 000 контактов/купивип3_433426 адресов.xlsx                                     
============================================================                                                                                                                                                       
Source name:         bigDB/Database Collection/XLSX Base Collection/База Kupivip.ru - 4 200 000 контактов/База Kupivip.ru - 4 200 000 контактов/купивип3_433426 адресов.xlsx                                       
Source hashtype:                                                                                                                                                                                                   
Source description:  Unattended import at 2019-03-15T20:07:22.742                                                                                                                                                  
[+] Finished adding /mnt/n0/leak/cleaning/bigDB/Database Collection/XLSX Base Collection/База Kupivip.ru - 4 200 000 контактов/База Kupivip.ru - 4 200 000 контактов/купивип3_433426 адресов.xlsx                  
                                                                                                                                                                                                                   
>> 3,629 FILES COMPLETED <<                                                                                                                                                                                        
                                                                                                                                                                                                                   
============================================================                                                                                                                                                       
 /mnt/n0/leak/cleaning/bigDB/Database Collection/XLSX Base Collection/10 млн e-mail адресов клиентов интернет магазинов/Wildberries/Ростовская обл..xlsx                                                           
============================================================                                                                                                                                                       
Source name:         bigDB/Database Collection/XLSX Base Collection/10 млн e-mail адресов клиентов интернет магазинов/Wildberries/Ростовская обл..xlsx                                                             
Source hashtype:
Source description:  Unattended import at 2019-03-15T20:07:22.759
[+] Finished adding /mnt/n0/leak/cleaning/bigDB/Database Collection/XLSX Base Collection/10 млн e-mail адресов клиентов интернет магазинов/Wildberries/Ростовская обл..xlsx

>> 3,630 FILES COMPLETED <<

============================================================
 /mnt/n0/leak/cleaning/bigDB/UPDATES/#1 November 4th 2018/checkyou/NextGenUpdate.com/Расшифровка NextGenUpdate.com [612k].txt
============================================================
Source name:         bigDB/UPDATES/#1 November 4th 2018/checkyou/NextGenUpdate.com/Расшифровка NextGenUpdate.com [612k].txt
Source hashtype:
Source description:  Unattended import at 2019-03-15T20:07:22.775
[+] Finished adding /mnt/n0/leak/cleaning/bigDB/UPDATES/#1 November 4th 2018/checkyou/NextGenUpdate.com/Расшифровка NextGenUpdate.com [612k].txt

>> 3,631 FILES COMPLETED <<

============================================================
 /mnt/n0/leak/cleaning/bigDB/UPDATES/#1 November 4th 2018/Update Dumps/nattyfree.com {3.715} [HASH+NOHASH] (Shopping Clothing)/NotFound.txt
============================================================
Source name:         bigDB/UPDATES/#1 November 4th 2018/Update Dumps/nattyfree.com {3.715} [HASH+NOHASH] (Shopping Clothing)/NotFound.txt
Source hashtype:
Source description:  Unattended import at 2019-03-15T20:27:05.939
'''

import os
import queue
import threading
from .db import DB
from .leak import *
from time import sleep
from .quickparse import *
from datetime import datetime
from multiprocessing import cpu_count
from pymongo.errors import ServerSelectionTimeoutError


class CredShedError(Exception):
    pass


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
                sys.stderr.write('[!] Error parsing source ID "{}"'.format(a))
                continue

    return n_array



class CredShed():

    def __init__(self, output='__db__', unattended=False, deduplication=False, threads=2):

        try:
            self.db = DB()
        except ServerSelectionTimeoutError as e:
            raise CredShedError('Connection to database timed out: {}'.format(str(e)))

        self.threads = threads
        self.output = Path(output)
        self.unattended = unattended
        self.deduplication = deduplication

        self.errors = []
        self.comms_queue = queue.Queue()
        self.print_lock = threading.Semaphore()

        # overwrite output file
        if not self.output.name == '__db__':
            with open(str(self.output), 'w') as f:
                f.write('')

        threading.Thread(target=self._tail_comms_queue, daemon=True).start()


    def search(self, query):
        '''
        query = search string(s)
        yields Account objects
        '''

        if type(query) == str:
            query = [query]

        for query in query:
            try:
                for result in self.db.find(str(query)):
                    #print('{}:{}@{}:{}:{}'.format(result['username'], result['email'], result['domain'], result['password'], result['misc']))
                    yield result

            except pymongo.errors.OperationFailure as e:
                raise CredShedError('Error querying MongoDB: {}'.format(str(e)))


    def stats(self):

        return self.db.stats(accounts=True, counters=True, sources=True, db=True)



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

            start_time = datetime.now()

            file_threads = int(self.threads*1.5)
            self.threads = 1

            pool = [None] * file_threads
            self._print('[+] {:,} files detected, adding in parallel ({} threads, 1 process per file)'.format(len(to_add), file_threads))

            completed = 0
            for l in to_add:
                while 1:
                    try:
                        for i in range(len(pool)):
                            t = pool[i]
                            if t is None or not t.is_alive():
                                if t is not None:
                                    completed += 1
                                    time_elapsed = datetime.now() - start_time 

                                    self._print('\n>> File "{}" finished ({:,} files completed in {}) <<\n'.format(t.name, completed, str(time_elapsed).split('.')[0]))
                                _t = threading.Thread(target=self._add_by_file, name=str(l[1]), args=(l,))
                                pool[i] = _t
                                _t.start()
                                # break out of infinite loop
                                assert False
                        sleep(.1)

                    except AssertionError:
                        break

            for t in pool:
                t.join()
                completed += 1
                self._print('\n>> File "{}" finished ({:,} files completed in {}) <<\n'.format(t.name, completed, str(time_elapsed).split('.')[0]))

            '''
            futures = []

            file_thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=file_threads)
            try:
                for l in to_add:
                    futures.append(file_thread_executor.submit(self._add_by_file, l))

                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    completed += 1
                    self._print('\n>> {:,} FILES COMPLETED <<\n'.format(completed))

            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
            finally:
                file_thread_executor.shutdown(wait=False)
            '''

        else:
            for l in to_add:
                self._add_by_file(l)


        if self.unattended and self.errors:
            self._print('Errors encountered:\n\t', end='')
            self._print('\n\t'.join(self.errors))



    def delete_leaks(self, leak_ids=[]):

        try:

            if leak_ids:

                to_delete = {}
                for source_id in number_range(leak_ids):
                    source_info = (self.db.get_source(source_id))
                    if source_info is not None:
                        to_delete[source_id] = str(source_id) + ': ' + str(source_info)

                if to_delete:
                    print('\nDeleting all entries from:\n\t{}'.format('\n\t'.join(to_delete.values())), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        start_time = datetime.now()

                        # disabling threads, since concurrent deletion of leaks
                        # leaves leftover accounts
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                            for source_id in to_delete:
                                executor.submit(self.db.remove_leak, source_id)

                        end_time = datetime.now()
                        time_elapsed = (end_time - start_time)                                
                else:
                    print('[!] No valid leaks specified were specified for deletion')

            else:

                while True:

                    assert self.db.sources.estimated_document_count() > 0, 'No more leaks in DB'
                    print(self.db.stats())
                    most_recent_source_id = self.db.most_recent_source_id()

                    try:
                        to_delete = int(input('Enter ID to delete [{}] (CTRL+C when finished): '.format(most_recent_source_id)) or most_recent_source_id)
                    except ValueError:
                        self._print('[!] Invalid entry', end='\n\n')
                        sleep(1)
                        continue

                    self._print('\nDeleting all entries from:\n\t{}: {}'.format(to_delete, str(self.db.get_source(to_delete))), end='\n\n')
                    if not input('OK? [Y/n] ').lower().startswith('n'):
                        start_time = datetime.now()
                        self.db.remove_leak(to_delete)
                        end_time = datetime.now()
                        time_elapsed = (end_time - start_time)
                        print('\n[+] Time Elapsed: {}\n'.format(str(time_elapsed).split('.')[0]))

        except KeyboardInterrupt:
            print('\n[*] Deletion cancelled')
            sys.exit(1)




    def _add_by_file(self, dir_and_file):
        '''
        takes iterable of directories and files in the format:
        [
            (leak_dir, leak_file)
            ...
        ]
        '''

        #self._print('[+] Initializing db for {}'.format(dir_and_file))
        db = DB()
        #self._print('[{}] Instantiated DB'.format(dir_and_file))

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

                #self._print('[+] Initializing QuickParse object for {}'.format(dir_and_file))
                q = QuickParse(file=leak_file, source_name=leak_friendly_name, unattended=self.unattended, strict=True)
                #self._print('[+] Finished initializing QuickParse object for {}'.format(dir_and_file))

            except QuickParseError as e:
                e = '[!] {}'.format(str(e))
                e2 = '[*] Falling back to non-strict mode'
                self.comms_queue.put(e)
                self.comms_queue.put(e2)
                q = QuickParse(file=leak_file, source_name=leak_friendly_name, unattended=self.unattended, strict=False)
                #self.errors.append(e)
                #self.errors.append(e2)

            except KeyboardInterrupt:
                self.comms_queue.put('\n[*] Skipping {}'.format(str(leak_file)))
                return

            leak = Leak(q.source_name, q.source_hashtype, q.source_misc)

            # see if source already exists
            source_already_in_db = db.sources.find_one(leak.source.document(misc=False, date=False))
            if source_already_in_db:
                if not self.unattended:
                    answer = input('Source ID {} ({}) already exists, merge? (Y/n)'.format(source_already_in_db['_id'], source_already_in_db['name'])) or 'y'
                    if not answer.lower().startswith('y'):
                        self.comms_queue.put('[*] Skipping existing source ID {} ({})'.format(source_already_in_db['_id'], source_already_in_db['name']))
                        return

            if not self.deduplication:
                # override set with generator
                leak.accounts = q.__iter__()

            else:
                account_counter = 0
                sself.comms_queue.put('[+] Deduplicating accounts')
                for account in q:
                    #self._print(str(account))
                    #try:
                    leak.add_account(account)
                    #except ValueError:
                    #    continue
                    account_counter += 1
                    if account_counter % 1000 == 0:
                        self._print('\r[+] {:,} '.format(account_counter), end='')
                self._print('\r[+] {:,}'.format(account_counter))


            if self.output.name == '__db__':

                #print('\nAdding:\n{}'.format(str(leak)))
                #file_thread_executor.submit(db.add_leak, leak, num_threads=options.threads)
                #self._print('[{}] Calling db.add_leak()'.format(dir_and_file))
                self.comms_queue.put(db.add_leak(leak, num_threads=self.threads))
                #self._print('[{}] Finished calling db.add_leak()'.format(dir_and_file))

            else:
                self._print('\n[+] Writing batch to {}\n'.format(str(self.output)))
                # open file in append mode because we may be parsing more than one file
                with open(str(self.output), 'wb+') as f:
                    for account in leak:
                        #self._print(str(account))
                        f.write(account.to_bytes() + b'\n')
                #leak.dump()

        finally:
            self.comms_queue.put('[+] Finished adding {}'.format(leak_file))
            db.close()


    def _tail_comms_queue(self):

        while 1:
            try:
                sys.stderr.write(self.comms_queue.get_nowait() + '\n')
            except queue.Empty:
                sleep(.1)
            except BrokenPipeError:
                return


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


    def _print(self, *s, end='\n'):

        s = [str(_) for _ in s]
        with self.print_lock:
            sys.stderr.write(' '.join(s) + end)