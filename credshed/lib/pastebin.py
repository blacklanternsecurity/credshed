import re
import json
import urllib
import logging
import requests
from time import sleep
from queue import Queue

log = logging.getLogger('credshed.pastebin')


class Paste():
    '''
    Generic "Paste" object to contain attributes of a standard paste
    '''

    email_regex = re.compile(r'[A-Z0-9_\-\.\+]+@[A-Z0-9_\-\.]+\.[A-Z]{2,8}', re.I)

    def __init__(self, _id):

        self.id = _id
        self.headers = None
        # update pastebin scrng api URL. Must have pastebin pro account to whitelist your IP
        self.url = f'https://scrape.pastebin.com/api_scrape_item.php?i={self.id}'
        self.num_emails = 0
        self.text = ''
        self.author = None


    def fetch(self, session, retries=2):

        while retries > 0:

            log.info(f'{"Re-" if retries < 2 else ""}Fetching {self.url}')

            try:
                self.text = session.get(self.url).text
                self.num_emails = len(self.email_regex.findall(self.text))
                break
            except requests.ConnectionError as e:
                log.warning(str(e))
                sleep(5)
                retries -= 1
                continue

        



class Pastebin():

    def __init__(self, loop_delay=60, scrape_limit=100, last_id=None):

        if not last_id:
            last_id = None

        self.ref_id = last_id
        self.queue = Queue()
        self.BASE_URL = 'http://pastebin.com'
        self.loop_delay = loop_delay
        self.scrape_limit = scrape_limit
        self.session = requests.Session()


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
            except:
                log.error('Error with pastebin')
                raw = None
                sleep(5)

        # import API result as JSON
        decoded = raw.read().decode('utf-8')
        try:
            raw_json = json.loads(decoded)
        except JSONDecodeError as e:
            log.error(str(e))
            log.error(str(decoded))
            sys.exit(1)

        results = []

        # populate results list with paste_ids
        for paste_listing in raw_json:
            results.append(paste_listing['key'])

        if not self.ref_id:
            results = results[:self.scrape_limit]

        for entry in results:
            paste = Paste(entry)
            # Check to see if we found our last checked paste_id
            if paste.id == self.ref_id:
                #if paste_id matches last checked id, no more new stuff
                break
            new_pastes.append(paste)

        for entry in new_pastes[::-1]:
            log.info('Queueing URL: ' + entry.url)
            self.queue.put(entry)


    def monitor(self):

        self.update()

        while 1:

            while not self.queue.empty():
                paste = self.queue.get()
                self.ref_id = paste.id
                self.import_paste(paste)
                
            self.update()

            while self.queue.empty():
                log.debug('No results. Sleeping.')
                sleep(self.loop_delay)
                self.update()


    def import_paste(self, paste):

        paste.fetch(self.session)
        if paste.num_emails > 0:
            log.info(f'Found {paste.num_emails} emails in {paste.url}')
            # todo: import to credshed
            for line in paste.text.splitlines()[:10]:
                log.info(f'    {line}')
