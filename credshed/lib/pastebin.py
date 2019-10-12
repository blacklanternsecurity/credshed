import re
import sys
import json
import string
import urllib
import logging
import requests
from time import sleep
from pathlib import Path
from datetime import datetime

log = logging.getLogger('credshed.pastebin')


class Paste():
    '''
    Generic "Paste" object to contain attributes of a standard paste
    '''

    email_regex = re.compile(r'[A-Z0-9_\-\.\+]+@[A-Z0-9_\-\.]+\.[A-Z]{2,8}', re.I)
    allowed_filename_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits

    def __init__(self, _id, date='', syntax='text', user='', title=''):

        self.id = _id
        self.url = f'https://scrape.pastebin.com/api_scrape_item.php?i={self.id}'
        self.text = ''
        self.date = date
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
            paste = Paste(p['key'], p['date'], p['syntax'], p['user'], p['title'])
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
                #try:
                self.import_paste(paste)

                # if failure, then put paste back in queue
                #except CredShedError as e:
                #    log.error(str(e))
                #    self.queue.insert(0, paste)
                
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

            log.debug(f'Importing {filename}')
            self.credshed.import_files(filename)

            if not self.keep_pastes:
                log.debug(f'Cleaning up {filename}')
                filename.unlink()