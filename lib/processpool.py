import logging
from time import sleep
from queue import Empty
import multiprocessing as mp


# set up logging
log = logging.getLogger('credshed.processpool')



class ProcessPool:
    '''
    usage:
    with ProcessPool(2) as pool:
        for i in pool.map(target, iterable):
            yield i
    '''

    def __init__(self, processes=None, daemon=False):

        if processes is None:
            processes = mp.cpu_count()

        self.processes = processes
        self.pool = [None] * self.processes

        self.daemon = daemon


    def map(self, func, iterable, args=(), kwargs={}):

        # make the result queue
        self.result_queue = mp.Queue(self.processes * 10)

        # loop until we're out of work
        started_counter = 0
        finished_counter = 0
        for entry in iterable:

            try:

                while 1:

                    for result in self.empty_result_queue():
                        yield result

                    # start processes
                    for i in range(len(self.pool)):
                        process = self.pool[i]
                        if process is None or not process.is_alive():
                            if process is not None:
                                finished_counter += 1
                                log.debug(f'{finished_counter:,} processes finished')
                            self.pool[i] = mp.Process(target=self.execute, args=(func,(entry,)+args), \
                                kwargs=kwargs, daemon=self.daemon)
                            self.pool[i].start()
                            started_counter += 1
                            log.debug(f'{started_counter:,} processes started')
                            # success, move on to next
                            assert False

                    # prevent unnecessary CPU usage
                    sleep(.1)

            except AssertionError:
                continue

        # wait for processes to finish
        while 1:

            for result in self.empty_result_queue():
                yield result

            finished_threads = [p is None or not p.is_alive() for p in self.pool]
            if all(finished_threads):
                finished_counter += len([p for p in self.pool if p is not None and not p.is_alive()])
                break
            else:
                log.debug(f'Waiting for {finished_threads.count(False):,} threads to finish')
                sleep(1)

        # collect last results
        for result in self.empty_result_queue():
            yield result

        if started_counter > 0:
            log.debug(f'{started_counter:,} processes started')
            log.debug(f'{finished_counter:,} processes finished')


    @staticmethod
    def empty_queue(q):

        while 1:
            try:
                yield q.get_nowait()
            except Empty:
                break


    def empty_result_queue(self):

        for result in self.empty_queue(self.result_queue):
            yield result


    def execute(self, func, args=(), kwargs={}):
        '''
        Executes given function and places return value in result queue
        '''

        self.result_queue.put(func(*args, **kwargs))


    @staticmethod
    def _close_queue(q):

        while 1:
            try:
                q.get_nowait()
            except Empty:
                break
        q.close()


    def __enter__(self):

        return self


    def __exit__(self, exception_type, exception_value, traceback):

        try:
            self._close_queue(self.result_queue)
        except:
            pass