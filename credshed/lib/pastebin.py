#!/usr/bin/env python3.7

# by TheTechromancer

import io
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

        from .core import parse_config

        self.credshed = credshed
        self.ref_id = None
        self.queue = []
        self.BASE_URL = 'http://pastebin.com'
        self.loop_delay = loop_delay
        self.keep_pastes = keep_pastes
        self.scrape_limit = scrape_limit
        self.session = requests.Session()
        self.config = parse_config()

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



class PasteBinReport():

    def __init__(self, pastebin, days=30, limit=20):

        log.info('Generating Pastebin report')

        self.pastebin = pastebin
        self.days = days
        self.limit = limit
        self.first_day = datetime.now() - timedelta(days=self.days)

        self.recent_leaks = []
        for recent_leak in self.pastebin.credshed.db.sources.find({
            'date': {'$gt': self.first_day},
            'name': {'$regex': r'\d{4}-\d{2}-\d{2}_pastebin_[a-zA-Z0-9_]*\.txt'}
        }):
            recent_leak = Source.from_document(recent_leak)
            self.recent_leaks.append(recent_leak)
        self.recent_leaks.sort(key=lambda x: x.size, reverse=True)
        self.total_accounts = sum([l.size for l in self.recent_leaks])

        self.domains = dict()
        for day in range(self.days):
            date = datetime.now() - timedelta(days=day)
            date = date.isoformat(timespec='hours').split('T')[0]
            report_filename = Path(self.pastebin.save_dir / f'{date}_pastebin_unique_accounts.txt')
            if report_filename.is_file():
                try:
                    leak = Leak()
                    leak.read(report_filename, strict=False, unattended=True)
                    for account in leak:
                        domain = account.email.split(b'@')[-1].decode()
                        try:
                            self.domains[domain] += 1
                        except KeyError:
                            self.domains[domain] = 1

                except QuickParseError as e:
                    log.error(str(e))
                    continue

        self.domains = list(self.domains.items())
        self.domains.sort(key=lambda x: x[-1], reverse=True)
        self.total_unique_accounts = sum([d[-1] for d in self.domains])



    def report(self):

        report_lines = []

        report_lines.append('=' * 80)
        report_lines.append(f'UNIQUE ACCOUNTS BY DOMAIN (TOTAL DOMAINS: {len(self.domains):,} / UNIQUE ACCOUNTS: {self.total_unique_accounts:,})')
        report_lines.append('=' * 80)
        report_lines.append(f'{"Accounts":<15}Domain')
        l = int(self.limit)
        for domain, count in self.domains:
            if count > 1:
                report_lines.append(f'{count:<15,.0f}{domain}')
                l -= 1
                if l <= 1:
                    break

        report_lines += self.top_leaks()

        return report_lines


    def top_leaks(self):

        report_lines = ['=' * 80]
        report_lines.append(f'TOP {self.limit:,} LEAKS IN THE PAST {self.days:,} DAYS (TOTAL: {len(self.recent_leaks):,} LEAKS / {self.total_accounts:,} ACCOUNTS)')
        report_lines.append('=' * 80)
        report_lines.append(f'{"Size":<15}Leak Name')
        l = int(self.limit)
        for recent_leak in self.recent_leaks:
            report_lines.append(str(recent_leak))
            l -= 1
            if l <= 1:
                break

        return report_lines


    def pie_unique_accounts(self):

        '''
        import plotly.graph_objects as go

        labels = [d[0] for d in self.domains[:self.limit]]
        values = [d[-1] for d in self.domains[:self.limit]]

        # Use `hole` to create a donut-like pie chart
        fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.3)])
        fig.layout.title = f'Unique Accounts by Domain (Last {self.days:,} Days)'
        fig.layout.template = 'plotly_dark'

        return fig
        '''
        import matplotlib.pyplot as plot

        # Pie chart, where the slices will be ordered and plotted counter-clockwise:
        labels = [d[0] for d in self.domains[:self.limit - 1]] + ['other']
        values = [d[-1] for d in self.domains[:self.limit - 1]] + [sum([d[-1] for d in self.domains[self.limit - 1:]])]
        explode = (.1,) + (0,) * (len(values) - 1)  # only "explode" the 1st slice

        fig, ax = plot.subplots()
        pie_chart = ax.pie(values, explode=explode, labels=labels, startangle=90, \
            autopct=lambda p: '{:.0f}'.format(p * sum(values) / 100))

        # set label text to white
        for autotext in pie_chart[2]:
            autotext.set_color('white')

        plot.legend(pie_chart[0], labels, bbox_to_anchor=(1,0.5), loc="center right", bbox_transform=plot.gcf().transFigure)
        pie_title = plot.title('Unique Accounts by Domain')
        plot.setp(pie_title, color='w')
        # equal aspect ratio ensures that pie is drawn as a circle.
        ax.axis('equal')
        # dark theme
        plot.style.use('dark_background')
        #plot.show()
        png_bytes = io.BytesIO()
        plot.savefig(png_bytes, format='png', edgecolor='none', bbox_inches='tight')
        png_bytes.seek(0)

        return png_bytes




    def email(self, to):

        assert all([Paste.email_regex.match(e) for e in to]), f'Invalid email: "{e}"'

        import smtplib
        from email.utils import make_msgid
        from email.message import EmailMessage

        msg = EmailMessage()
        pie_png_bytes = self.pie_unique_accounts().read()

        # set the plain text body
        msg.set_content('\n'.join(self.report()))

        # now create a Content-ID for the image
        image_cid = make_msgid(domain='credshed.com')

        top_leaks = '\n'.join(self.top_leaks())

        header = '\n'.join([
            '=' * 80,
            f'{self.total_unique_accounts:,} UNIQUE ACCOUNTS IN THE PAST {self.days:,} DAYS ({self.total_accounts:,} TOTAL)',
            '=' * 80
        ])

        # set an alternative html body
        msg.add_alternative(f"""\
        <html>
          <table bgcolor="#000000" style="color: white;padding: 1rem;">
            <thead>
              <tr><td>
              <h1 style='font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important'>
                  c r e d s h e d
              </h1>
              </td></tr>
            </thead>
            <tbody>
              <tr><td>
                <p><pre><code style="color: white">
{header}
                </code></pre></p>
              </td></tr>
              <tr><td>
                <img src="cid:{image_cid[1:-1]}">
              </td></tr>
              <tr><td>
                <p><pre><code style="color: white">
{top_leaks}
                </code></pre></p>
              </td></tr>
            </tbody>
          </table>
        </html>
        """, subtype='html')
        # image_cid looks like <long.random.number@xyz.com>
        # to use it as the img src, we don't need `<` or `>`
        # so we use [1:-1] to strip them off

        # now open the image and attach it to the email
        msg.get_payload()[1].add_related(pie_png_bytes, maintype='image', subtype='png', cid=image_cid)

        # the message is ready now

        # Send the message via our own SMTP server.
        # generic email headers
        msg['Subject'] = f'CredShed Scraping Report {datetime.now().isoformat(timespec="hours").split("T")[0]}'
        try:
            msg['From'] = self.pastebin.config['EMAIL ALERTS']['from']
            mail_server = self.pastebin.config['EMAIL ALERTS']['mail_server']
            mail_port = self.pastebin.config['EMAIL ALERTS']['mail_port']
            auth_user = self.pastebin.config['EMAIL ALERTS']['auth_user']
            auth_pass = self.pastebin.config['EMAIL ALERTS']['auth_pass']
        except KeyError as e:
            log.critical(f'Error parsing credshed.config: {e}')
            return

        try:
            log.info('Connecting to email server')
            s = smtplib.SMTP(mail_server, mail_port)
            s.ehlo()
            s.starttls()
            s.login(auth_user, auth_pass)
            for email_address in to:
                log.info(f'Sending email to {email_address}')
                msg['To'] = f'<{email_address}>'
            s.send_message(msg)
            s.quit()
            log.info('Finished sending email')
        except smtplib.SMTPException as e:
            log.critical(f'Error sending email: {e}')