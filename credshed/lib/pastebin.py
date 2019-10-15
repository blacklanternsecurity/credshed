#!/usr/bin/env python3.7

# by TheTechromancer

import re
import sys
import json
import queue
import string
import urllib
import logging
import requests
import threading
from .leak import *
from .errors import *
from time import sleep
from pathlib import Path
from datetime import datetime, timedelta

log = logging.getLogger('credshed.pastebin')


class Paste():
    '''
    Generic "Paste" object to contain attributes of a standard paste
    '''

    email_regex = re.compile(r'[A-Z0-9_\-\.\+]+@[A-Z0-9_\-\.]+\.[A-Z]{2,8}', re.I)
    allowed_filename_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits

    def __init__(self, _id, syntax='text', user='', title=''):

        self.id = _id
        self.url = f'https://scrape.pastebin.com/api_scrape_item.php?i={self.id}'
        self.text = ''
        self.date = datetime.now().isoformat(timespec='hours').split('T')[0]
        self.user = user
        self.title = title
        self.syntax = syntax
        self.num_lines = 0
        self.num_emails = 0


    def fetch(self, session, retries=2):

        while retries > 0:

            log.debug(f'{"Re-f" if retries < 2 else "F"}etching {self.url}')

            try:
                self.text = session.get(self.url).text
                for line in self.text.splitlines():
                    self.num_lines += 1
                    if self.email_regex.match(line):
                        self.num_emails += 1
                break
            except requests.ConnectionError as e:
                log.warning(str(e))
                sleep(5)
                retries -= 1
                continue


    @property
    def filename(self):
        '''
        returns recommended filename
        '''

        filename_parts = []
        for i in (self.syntax, self.user, self.title, self.id):
            if i:
                cleaned_text = ''.join([c for c in i if c in self.allowed_filename_chars])
                filename_parts.append(cleaned_text)

        return f'{self.date}_pastebin_{"_".join(filename_parts)}.txt'


        



class Pastebin():

    def __init__(self, credshed, loop_delay=60, scrape_limit=100, save_dir=None, keep_pastes=True):

        self.credshed = credshed
        self.ref_id = None
        self.queue = []
        self.BASE_URL = 'http://pastebin.com'
        self.loop_delay = loop_delay
        self.keep_pastes = keep_pastes
        self.scrape_limit = scrape_limit
        self.session = requests.Session()

        if save_dir is None:
            save_dir = Path.cwd()
        self.save_dir = Path(save_dir)


    def update(self):
        '''
        Fills queue with new Pastebin IDs
        '''

        log.info('Retrieving {:,} newest pastes'.format(self.scrape_limit))
        new_pastes = []
        raw = None

        while not raw:
            try:
                raw = urllib.request.urlopen(f'https://scrape.pastebin.com/api_scraping.php?limit={self.scrape_limit}')
            except Exception as e:
                log.error(f'Error with pastebin: {e}')
                raw = None
                sleep(5)

        # import API result as JSON
        decoded = raw.read().decode('utf-8')
        try:
            json_results = json.loads(decoded)
        except json.decoder.JSONDecodeError as e:
            log.error(f'JSON parsing error: {e}')
            log.error(str(decoded))
            sys.exit(1)

        if not self.ref_id:
            json_results = json_results[:self.scrape_limit]

        for p in json_results:
            paste = Paste(p['key'], p['syntax'], p['user'], p['title'])
            # check to see if we found our last checked paste_id
            if paste.id == self.ref_id:
                # if paste_id matches last checked id, no more new stuff
                break
            new_pastes.append(paste)

        for entry in new_pastes[::-1]:
            #log.info('Queueing URL: ' + entry.url)
            self.queue.insert(0, entry)


    def monitor(self):

        self.update()

        while 1:

            for _ in range(len(self.queue)):

                paste = self.queue.pop()
                self.ref_id = paste.id

                # try to import
                try:
                    self.import_paste(paste)

                # if failure, then put paste back in queue
                except CredShedError as e:
                    log.error(str(e))
                    self.queue.insert(0, paste)
                
            self.update()

            while not self.queue:
                log.debug('No results. Sleeping.')
                sleep(self.loop_delay)
                self.update()


    def import_paste(self, paste):

        paste.fetch(self.session)

        # if there's at least one email for every 100 lines of text
        if (paste.num_emails / paste.num_lines) > .01:

            filename = self.save_dir / paste.filename
            log.info(f'Found {paste.num_emails:,} emails in {paste.filename}')

            with open(filename, 'w') as f:
                f.write(paste.text)

            # keep track of unique accounts
            if self.keep_pastes:
                threading.Thread(target=self._tail_unique_account_queue, args=(self.credshed.unique_account_queue,), daemon=True).start()

            log.debug(f'Importing {filename}')
            self.credshed.import_files(filename, show_unique=(not self.keep_pastes))

            if not self.keep_pastes:
                log.debug(f'Cleaning up {filename}')
                filename.unlink()




    def report(self, days=30, limit=20):

        first_day = datetime.now() - timedelta(days=days)
        recent_leaks = []
        for recent_leak in self.credshed.db.sources.find({
            'date': {'$gt': first_day},
            'name': {'$regex': r'\d{4}-\d{2}-\d{2}_pastebin_[a-zA-Z0-9_]*\.txt'}
        }):

            recent_leak = Source.from_document(recent_leak)
            recent_leaks.append(recent_leak)

        recent_leaks.sort(key=lambda x: x.size, reverse=True)
        log.info('=' * 80)
        log.info(f'TOP {limit:,} LEAKS IN THE PAST {days:,} DAYS (TOTAL: {len(recent_leaks):,})')
        log.info('=' * 80)
        log.info(f'{"Size":<15}Leak Name')
        l = int(limit)
        for recent_leak in recent_leaks:
            log.info(recent_leak)
            l -= 1
            if l <= 1:
                break

        domains = dict()
    
        for day in range(days):
            date = datetime.now() - timedelta(days=day)
            date = date.isoformat(timespec='hours').split('T')[0]
            report_filename = str(self.save_dir / f'{date}_pastebin_unique_accounts.txt')
            try:
                leak = Leak()
                leak.read(report_filename, strict=False, unattended=True)
                for account in leak:
                    domain = account.email.split(b'@')[-1].decode()
                    try:
                        domains[domain] += 1
                    except KeyError:
                        domains[domain] = 1

            except QuickParseError as e:
                log.error(str(e))
                continue

        domains = list(domains.items())
        domains.sort(key=lambda x: x[-1], reverse=True)
        total_unique_accounts = sum([d[-1] for d in domains])
        log.info('=' * 80)
        log.info(f'UNIQUE ACCOUNTS BY DOMAIN (DOMAINS: {len(domains):,} / UNIQUE ACCOUNTS: {total_unique_accounts:,})')
        log.info('=' * 80)
        log.info(f'{"Accounts":<15}Domain')
        l = int(limit)
        for domain, count in domains:
            if count > 1:
                log.info(f'{count:<15,.0f}{domain}')
                l -= 1
                if l <= 1:
                    break





    def _tail_unique_account_queue(self, unique_account_queue):
        
        while 1:
            date = datetime.now().isoformat(timespec='hours').split('T')[0]
            filename = self.save_dir / f'{date}_pastebin_unique_accounts.txt'
            with open(filename, 'ab') as f:
                while 1:
                    try:
                        account = unique_account_queue.get_nowait()
                        log.debug(f'Writing account {account}')
                        f.write(account.bytes + b'\n')
                    except queue.Empty:
                        sleep(.1)
                        break