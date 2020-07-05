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
import concurrent.futures
from lib.credshed import *
from lib import validation
from lib.parser import File
from lib.processpool import *
from datetime import datetime
from lib import util as core_util
from lib.filestore import util as filestore_util

# set up logging
log = logging.getLogger('credshed.cli')


class CredShedCLI(CredShed):

    def __init__(self, options):

        super().__init__()
        self.options = options

    def search(self):

        start_time = datetime.now()
        num_accounts_in_db = self.db.index_size()

        left = int(self.options.limit) - 1

        num_results = 0
        for keyword in self.options.search:
            if self.options.limit == -1 or left > 0:
                query_type = validation.validate_query_type(keyword, self.options.query_type)
                log.info(f'Searching by {query_type}: {keyword}')

                for account in super().search(keyword, limit=left):
                    if self.options.print0:
                        sys.stdout.buffer.write(account.bytes + b'\n')
                    else:
                        print(str(account))
                    num_results += 1
                    if self.options.limit > 0:
                        if left <= 0:
                            break
                        left -= 1

        end_time = datetime.now()
        time_elapsed = (end_time - start_time)
        log.info(f'Searched {num_accounts_in_db:,} accounts in {str(time_elapsed)[:-4]} seconds')
        if options.limit > 0:
            total_count = 0
            for keyword in self.options.search:
                total_count += self.count(keyword, self.options.query_type)
            if total_count >= 10000:
                total_count = f'{max(total_count, num_results):,}+'
            else:
                total_count = f'{total_count:,}'
            log.info(f'Showing {num_results:,}/{total_count} results')
        else:
            log.info(f'{num_results:,} results for "{" + ".join(self.options.search)}"')


    def query_stats(self):

        for keyword in self.options.search:
            stats = super().query_stats(keyword)
            log.info(stats)


    def db_stats(self):

        print(super().db_stats())


    def import_file(self, filename, options):

        try:
            return super().import_file(
                filename,
                unattended=options.unattended,
                force=options.force_ingest,
                stdout=options.stdout,
                force_ascii=False
            )

        except CredShedDatabaseError:
            return super().import_file(
                filename,
                unattended=options.unattended,
                force=options.force_ingest,
                stdout=options.stdout,
                force_ascii=True
            )

        except KeyboardInterrupt:
            log.critical('Interrupted')
            return (0,0)


    def import_files(self):
        '''
        benchmark for full /etc import (1,500 files):
            3 process, main thread: 2:13
            3 processes: 1:27

        benchmark for rockyou-accounts-1M.txt:
            --threads 10, 3 node cluster, replicas 0: 2:40
            --threads 10, single node, replicas 0: 2:26
        '''

        total_accounts = 0
        unique_accounts = 0

        # total number of files processed
        processed_files = 0
        # number of files that contained at least one account
        interesting_files = 0

        major_start_time = datetime.now()

        # make a list of all files (excluding compressed ones)
        filelist = list(set(core_util.recursive_file_list(self.options.ingest)))
        total_file_count = len(filelist)
        log.info(f'Importing a total of {len(filelist):,} files')

        # there shouldn't be more threads than files
        #file_threads = min(10, len(filelist))

        # make temporary config changes to speed up import
        if not self.options.stdout:
            self.db.optimize_for_indexing()

        # if unattended, spawn processes like there's no tomorrow
        if self.options.unattended and self.options.threads > 1:

            # we only parallelize files larger than 2MB
            parallelization_threshold_bytes = 2000000

            # because os.fork() is expensive
            large_files = [f for f in filelist if f.size > parallelization_threshold_bytes]
            filelist = [f for f in filelist if f.size <= parallelization_threshold_bytes]

            # ensure total number of threads stay consistent
            #self.options.threads = max(1, int(self.options.threads/file_threads))
            if large_files:
                log.info(f'Importing {len(large_files):,} files using {self.options.threads:,} file threads')

                with ProcessPool(self.options.threads, name='Import') as pool:
                    for unique, total in pool.map(self.import_file, large_files, (self.options,)):
                        processed_files += 1
                        if total > 0:
                            interesting_files += 1
                        unique_accounts += unique
                        total_accounts += total

                        progress_time = datetime.now()
                        time_elapsed = (progress_time - major_start_time).total_seconds()
                        log.info(
                            'Imported {:,}/{:,}/{:,} files in {:02d}:{:02d}:{:02d}'.format(
                                interesting_files,
                                processed_files,
                                total_file_count,
                                int(time_elapsed // 3600),
                                int((time_elapsed % 3600) // 60),
                                int(time_elapsed % 60)
                            )
                        )

        # use normal Python threading for all the smaller files
        if filelist:
            log.info(f'Importing {len(filelist):,} files using main thread')
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.options.threads) as thread_pool:
                results = [thread_pool.submit(self.import_file, filename, options) for filename in filelist]
                for result in concurrent.futures.as_completed(results):
                    unique,total = result.result()
                    processed_files += 1
                    if total > 0:
                        interesting_files += 1
                    unique_accounts += unique
                    total_accounts += total

                    progress_time = datetime.now()
                    time_elapsed = (progress_time - major_start_time).total_seconds()
                    log.info(
                        'Imported {:,}/{:,}/{:,} files in {:02d}:{:02d}:{:02d}'.format(
                            interesting_files,
                            processed_files,
                            total_file_count,
                            int(time_elapsed // 3600),
                            int((time_elapsed % 3600) // 60),
                            int(time_elapsed % 60)
                        )
                    )


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

        # set config back to normal
        if not self.options.stdout:
            self.db.optimize_for_indexing(reset=True)


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
    '''
    exploit.in import benchmarks (680,575,885 unique / 796,787,228 total):
        10 nodes, 20 CPUs each, 6GB index mem, 19GB JVM mem, 100 shards:
            - starts off at 3.3M per minute (660K / minute * 5 file threads)
            - after 100M documents, slows to ~500K per minute
            - after 150M documents, slows to ~400K per minute
        20 nodes, 10 CPUs each, 3GB index mem, 10GB JVM mem, 20 shards:
            - starts off at ~500K per minute
        10 nodes, 20 CPUs each, 9.5GB index mem, 19GB JVM mem, 1000 shards:
            - starts off at 5.5M per second
            - quickly drops to basically nothing
        10 nodes, 20 CPUs each, 10GB index mem, 19GB JVM mem, 200 shards:
            - starts off super slow, ~100K per second
            - speeds up a LOT after a few minutes, 3.5M per second
            - after 50M documents, slows to ~150K per minute
        1 node, all CPUs, 150GB JVM mem, 5 shards:
            - starts off at 3.5M per minute
            - slowly decreases, ~800K per minute at 500M documents
            - total time elapsed: 755m 42s
        1 node, all CPUs, 200GB JVM mem, 50 shards:
            - starts off at 3.5M per minute
            - quickly drops to <500k per minute
        1 node, all CPUs, 200GB JVM mem, 50GB index mem, 10 shards:
            - starts off at 1.4M per minute
            - quickly increases to 6.5M per minute
            - evens out at 1.3M per minute
            - total time elapsed: 660m 15s
        1 node, all CPUs, 200GB JVM mem, 50GB index mem, 20 shards:
            - starts off at 1.4M per minute
            - evens out at 800K per minute
            - total time elapsed: 846m 55s
        1 node, all CPUs, 200GB JVM mem, 50GB index mem, 2 shards:
            - starts off at 5M per minute
            - quickly drops to 2M per minute
            - evens out at 1M per minute
            - total time elapsed: 585m 14s
            - 686,345,232/803,126,569
            - 2nd run total time elapsed: 460m 43s
            - 686,029,758/803,126,569
        1 node, all CPUs, 200GB JVM mem, 50GB index mem, 1 shard:
            - starts off at 5M per minute
            - evens out at 1.2M per minute
            - total time elapsed: 764m 58s
            - 686,273,343/803,126,569
        1 node, all CPUs, 200GB JVM mem, 50GB index mem, 3 shards:
            - starts off at 5M per minute
            - evens out at 1.1M per minute
            - total time elapsed: 644m 48s
            - 686,362,834/803,126,569
    '''

    try:

        try:
            credshed = CredShedCLI(options)
        except CredShedError as e:
            log.critical('{}: {}\n'.format(e.__class__.__name__, str(e)))
            sys.exit(1)

        # if we're importing stuff
        try:
            if options.drop:
                log.critical('--drop DELETES ALL DATA FROM THE DATABASE')
                log.critical('Press CTRL+C within 5 seconds to cancel')
                sleep(5)
                credshed.drop()

            if options.ingest:
                credshed.import_files()

            elif options.delete_leak is not None:
                credshed.delete_leak()

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

    except KeyboardInterrupt:
        log.critical('Interrupted')

    except Exception as e:
        import traceback
        log.critical(traceback.format_exc())
        


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    num_cores = multiprocessing.cpu_count()
    default_threads = min(5, int(num_cores))

    parser.add_argument('search',                       nargs='*',                      help='search term(s)')
    parser.add_argument('-q', '--query-type',           default='auto',                 help='query type (email, domain, or username)')
    parser.add_argument('-i', '--ingest',   type=Path,  nargs='+',                      help='import files or directories into the database')
    parser.add_argument('-f', '--force-ingest',         action='store_true',            help='also ingest files which have already been imported')
    parser.add_argument('-db', '--db-stats', action='store_true',                       help='show all imported leaks and DB stats')
    parser.add_argument('-s', '--stdout',   action='store_true',                        help='when importing, write to stdout instead of database (null-byte delimited, use tr \'\\0\')')
    parser.add_argument('-d', '--delete-leak',          nargs='*',                      help='delete leak(s) from database, e.g. "1-3,5,7-9"', metavar='SOURCE_ID')
    parser.add_argument('-dd', '--deduplication',       action='store_true',            help='deduplicate accounts ahead of time (lots of memory usage on large files)')
    parser.add_argument('--drop',                       action='store_true',            help='delete the entire database D:')
    parser.add_argument('--threads',        type=int,   default=default_threads,        help='number of threads for import operations')
    parser.add_argument('--print0',                     action='store_true',            help='delimit search results by null byte instead of colon')
    parser.add_argument('--limit',          type=int,   default=-1,                     help='limit number of results (default: unlimited)')
    parser.add_argument('-u', '--unattended',           action='store_true',            help='auto-detect import fields without user interaction')
    parser.add_argument('-v', '--verbose',              action='store_true',            help='show what is happening')
    parser.add_argument('--debug',                      action='store_true',            help='display detailed debugging info')

    try:

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(0)

        logging.getLogger('credshed').setLevel(logging.INFO)

        options = parser.parse_args()

        if options.verbose or options.debug:
            logging.getLogger('credshed').setLevel(logging.DEBUG)
            options.verbose = True
            # elastic debug logging

        if options.debug:
            es_trace_logger = logging.getLogger('elasticsearch')
            es_trace_logger.setLevel(log.getEffectiveLevel())
            es_trace_logger.addHandler(logger.console)

        if options.ingest and not options.unattended:
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