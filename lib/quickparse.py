#!/usr/bin/env python3.7

'''
TODO:
    clean up code, split gather_info() into separate functions
'''

import random
import string
from .db import *
from .leak import *
from time import sleep
from pathlib import Path
from datetime import datetime
from subprocess import run, PIPE
from statistics import mode, StatisticsError


# custom error classes

class QuickParseError(Exception):
    pass

class DelimiterError(QuickParseError):
    pass

class FieldDetectionError(QuickParseError):
    pass




class QuickParse():
    '''
    takes a filename
    yields Account() objects
    '''

    def __init__(self, file, source_name=None, unattended=False, threshold=.8):

        self.file = Path(file).resolve()

        if source_name is None:
            self.source_name = str(file)
        else:
            self.source_name = str(source_name)
        

        self.source_hashtype = ''

        self.output_delimiter = b'\x00'
        self.input_delimiter = b':'
        self.num_input_fields = 2    # number of input fields, for edge case where password contains delimiter character
        self.password_field = 1      # used in combination with num_input_fields
        self.unattended = unattended # whether to parse files automatically
        self.threshold = threshold   # if less than this percentage of lines don't comply, skip file

        self.info_gathered = False

        # email:username:password:misc
        self.fields = {
            'e': 0, # email
            'u': 1, # username
            'p': 2, # password
            'h': 3, # hash
            'm': 4  # misc
        }

        # input_position --> output_position
        self.mapping = dict()

        # gather information about source
        self.gather_source_info(file)
        self.gather_info()



    def gather_info(self, num_lines=100):
        '''
        gather information about how to parse the file
        such as delimiter, field order, etc.
        '''

        # make sure file exists
        assert self.file.is_file(), 'Failure reading {}'.format(str(self.file))

        head = [x for x in run(['head', '-n', str(int(num_lines/2)), str(self.file)], stdout=PIPE).stdout.splitlines() if x]
        tail = [x for x in run(['tail', '-n', str(int(num_lines/2)), str(self.file)], stdout=PIPE).stdout.splitlines() if x]

        # deduplicate, just in case file is smaller than num_lines
        all_lines = list(set(head + tail))
        self.input_delimiter = self._get_delimiter(all_lines)

        # confirm delimiter if not unattended
        if not self.unattended:
            self._confirm_delimiter(all_lines)

        # get number of input fields, for ensuring that passwords
        # containing the delimiter character get parsed correctly
        try:
            self.num_input_fields = mode([line.count(self.input_delimiter) for line in all_lines]) + 1
        except StatisticsError:
            self.num_input_fields = 0

        if self.num_input_fields < 2:
            if self.unattended:
                raise FieldDetectionError('not enough input fields detected')
            else:
                self.num_input_fields = int(input('How many fields? > ')) or 2

        # detect what type of data is in each field
        # weed out the easy stuff (emails, hashes, blank columns)
        columns, unknown_fields = self._detect_fields(all_lines)

        if unknown_fields:

            # try and figure the rest out
            if len(unknown_fields) == 1:
                errprint('[+] Assuming passwords in column {}'.format(unknown_fields[0]))
                self.password_field = unknown_fields[0]
                self.mapping[unknown_fields[0]] = self.fields['p']
                unknown_fields = []

            elif len(unknown_fields) == 2:
                self.password_field = unknown_fields[1]
                errprint('[+] Assuming usernames in column {}'.format(unknown_fields[0]))
                self.mapping[unknown_fields[0]] = self.fields['u']
                errprint('[+] Assuming passwords in column {}'.format(unknown_fields[1]))
                self.mapping[unknown_fields[1]] = self.fields['p']
                unknown_fields = []

            elif self.unattended:
                # die alone, in the dark
                raise TypeError('Unknown column in {}'.format(self.file))


        # ask for help
        while not self.info_gathered == True:
            for i in unknown_fields:
                column = columns[i]
                if all([field == '' for field in column]):
                    continue
            
                errprint('  ' + '\n  '.join(column))

                # assume last field is password if email/username is already mapped
                #if auto:
                #    id_mapped = any([f in self.mapping.values() for f in (self.fields['u'], self.fields['e'])])
                #    last_column = all([all([f == '' for f in c]) for c in columns[i+1:]])
                #    # print('[+] id_mapped: {}, last_column: {}'.format(id_mapped, last_column))
                #    if id_mapped and last_column:

                #        self.password_field = i
                #        self.mapping[i] = self.fields['p']
                #        self.info_gathered = True
                #        break

                if self.unattended:
                    raise TypeError('Unknown column in {}'.format(self.file))
                # otherwise, ask user
                errprint('=' * 60)
                errprint('[?] Which column is this?')
                errprint('=' * 60)
                field = input('[E]mail | [U]ser | [P]assword | [H]ash | [M]isc | [enter] to skip > ').strip().lower()
                if any([field.startswith(f) for f in self.fields.keys()]):
                    self.mapping[i] = self.fields[field[0]]
                    if field == 'p':
                        self.password_field = i
                elif not field:
                    errprint('[*] Skipped')
                    continue
                else:
                    errprint('[!] Please try again')
                    sleep(1)

            # must have at least two fields
            if not (any([i in self.mapping.values() for i in (self.fields['u'], self.fields['e'])]) and \
                any([i in self.mapping.values() for i in (self.fields['p'], self.fields['h'], self.fields['m'])])):
                #raise ValueError('Not enough fields mapped in {}'.format(file))
                errprint('[!] Not enough fields mapped')
                self.mapping.clear()
                unknown_fields = list(range(self.num_input_fields))
                continue

            translated_lines = []
            for line in all_lines:
                try:
                    translated_lines.append(str(self.translate_line(line)))
                except AccountCreationError as e:
                    errprint('[!] {}: {}'.format(str(e), str(line)))
                    continue

            # display and confirm selection
            errprint(('=' * 60))
            errprint('email:username:password:misc/description')
            errprint('=' * 60)
            for _ in range(min(20, len(translated_lines))):
                line = random.choice(translated_lines)
                translated_lines.remove(line)
                #try:
                errprint(' ' + line)
                #    #errprint(line.decode().replace(self.output_delimiter.decode(), ':'))
                #except UnicodeDecodeError:
                #    continue
            errprint('=' * 60)

            if self.unattended:
                errprint('[+] Unattended parsing of {} was successful\n'.format(self.file))
                self.info_gathered = True
            else:
                if not input('\nOK? [Y/n] ').lower().startswith('n'):
                    self.info_gathered = True
                else:
                    self.mapping.clear()
                    unknown_fields = list(range(self.num_input_fields))



    def gather_source_info(self, file):
        
        if self.unattended:
            self.source_misc = 'Unattended import at ' + datetime.now().isoformat(timespec='milliseconds')
        else:
            try:
                self.source_misc = 'Manual import at ' + datetime.now().isoformat(timespec='milliseconds')
                self.source_name = self.file.stem.split('-')[0]
                self.source_hashtype = self.file.stem.split('-')[1].upper()

            except IndexError:
                self.source_hashtype = ''

        #except TypeError:
        #    self.source_name, self.source_hashtype = ('unknown', 'unknown')

        #finally:
        errprint('=' * 60)
        errprint(' ' + str(self.file))
        errprint('=' * 60)
        if self.unattended:
            errprint('Source name:         {}'.format(self.source_name))
            errprint('Source hashtype:     {}'.format(self.source_hashtype))
            errprint('Source description:  {}'.format(self.source_misc))
        else:
            self.source_name = input('Source name: [{}] '.format(self.source_name)) or self.source_name
            self.source_hashtype = input('Source hashtype: [{}] '.format(self.source_hashtype)) or self.source_hashtype
            self.source_misc = input('Source description: [{}] '.format(self.source_misc)) or self.source_misc



    def translate_line(self, line):
        '''
        converts each line to an Account() object
        '''

        line = [f.strip(b'\r\n') for f in line.split(self.input_delimiter)]
        len_diff = len(line) - self.num_input_fields
        line_new = [b''] * 5

        for p in self.mapping:
            if len_diff and p == self.password_field:
                # handle edge case where password contains delimiter character
                line_new[self.mapping[p]] = self.input_delimiter.join(line[p:p+len_diff+1])
            else:
                line_new[self.mapping[p]] = line[p]

        else:
            email, username, password, _hash, misc = line_new
            return Account(email, username, password, _hash, misc)




    def _get_delimiter(self, lines):
        '''
        delimiter is the non-alphanumeric character with the most consistent per-line count
        '''
        per_line_char_counts = dict()
        # count number of special characters for each line
        for i in range(len(lines)):
            line = lines[i]
            for j in range(len(line)):
                char = line[j:j+1]
                if not (char.isalnum() or char in [b'@', b'.', b'!', b'?', b'(', b')']):
                    try:
                        per_line_char_counts[char]
                    except KeyError:
                        per_line_char_counts[char] = dict()
                    try:
                        per_line_char_counts[char][i] += 1
                    except KeyError:
                        per_line_char_counts[char][i] = 1

        # which characters have the most consistent line count?
        # consistency_scores: dictionary in the format:
        # { char: ( consistency_score, most_common_per_line_count ) }
        consistency_scores = dict()
        for char in per_line_char_counts:
            num_occurrences = list(per_line_char_counts[char].values())
            try:
                most_common_per_line_count = mode(num_occurrences)
                score = num_occurrences.count(most_common_per_line_count)
            except StatisticsError:
                continue
            consistency_scores[char] = ( score, most_common_per_line_count )

        consistency_scores = list(consistency_scores.items())
        # first sort by most common per-line count
        consistency_scores.sort(key=lambda x: x[1][1], reverse=True)
        # then sort by highest consistency score
        consistency_scores.sort(key=lambda x: x[1][0], reverse=True)

        try:
            best_delimiter, (score, per_line_count) = consistency_scores[0]
        except IndexError:
            raise DelimiterError('No delimiter candidates found in file "{}"'.format(self.file))

        # do some additional checks if unattended
        if self.unattended:
            d0 = consistency_scores[0]
            if len(consistency_scores) > 1:

                # handle a tie
                ties = [s for s in consistency_scores if s[1][0] == d0[1][0] and s[1][1] == d0[1][1]]

                if len(ties) > 1:
                    ties_str = b'" "'.join([s[0] for s in ties])
                    raise DelimiterError('Multiple delimiter candidates: "{}" in file "{}"'.format(str(ties_str)[2:-1], self.file))

            # make sure most lines fit the detected format
            if (score / len(lines)) < .8:
                raise DelimiterError('Inconsistent delimiter "{}" in file "{}"'.format(str(d0[0])[2:-1], self.file))

        # return top character
        return best_delimiter



    def _confirm_delimiter(self, lines):

        # print 20 random lines
        l = [_ for _ in lines]
        errprint('\n' + '=' * 60)
        for _ in range(min(20, len(lines))):
            rand_choice = random.choice(l)
            l.remove(rand_choice)
            print(' ' + str(rand_choice)[2:-1])
        errprint('=' * 60)
        self.input_delimiter = input('Delimiter [{}] > '.format(str(self.input_delimiter)[2:-1])).encode() or self.input_delimiter

        # handle case where delimiter is hexidecimal
        hex_prefixes = [b'\\x', b'0x']
        new_delimiter = []
        if any([x in self.input_delimiter for x in hex_prefixes]):
            i = 0
            for _ in range(len(self.input_delimiter)):
                if self.input_delimiter[i:i+2] in hex_prefixes:
                    hex_chunk = self.input_delimiter[i+2:i+4]
                    try:
                        new_delimiter.append(bytes.fromhex(hex_chunk.decode()))
                        i += 4
                        continue
                    except ValueError:
                        pass

                new_delimiter.append(self.input_delimiter[i:i+1])
                i += 1

            self.input_delimiter = new_delimiter

        errprint('[+] Using delimiter: {}'.format(str(self.input_delimiter)))



    def _detect_fields(self, lines):

        unknown_fields = []
        columns = [[] for i in range(self.num_input_fields)]
        for i in range(self.num_input_fields):
            
            # build column
            column = []
            for line in lines:
                try:
                    field = line.split(self.input_delimiter)[i]
                    field = field.decode()
                    column.append(field)
                except IndexError:
                    column.append('')
                except UnicodeDecodeError:
                    column.append(str(field)[2:-1])


            column_no_blanks = [f for f in column if f]
            if column_no_blanks:
                # take a field length from somewhere in the middle
                random_field_length = len(column_no_blanks[int(len(column_no_blanks)/2)])
            else:
                # skip blank columns
                continue

            # detect emails
            num_emails = [Account.is_email(field) for field in column].count(True)
            if num_emails > int(.75 * len(lines)) and not self.fields['e'] in self.mapping.values():
                errprint('[+] Detected emails in column {}'.format(i))
                self.mapping[i] = self.fields['e']

            # detect hashes
            # all non-blank fields in column must be the same length
            # and be at least 12 characters in length
            # and contain only hex characters
            elif random_field_length >= 12:
                if [len(field) == random_field_length for field in column_no_blanks].count(True)/len(column_no_blanks) > self.threshold:
                    if [all([char.lower() in 'abcdef0123456789' for char in field]) for field in column_no_blanks].count(True)/len(column_no_blanks) > self.threshold:
                        errprint('[+] Detected hashes in column {}'.format(i))
                        self.mapping[i] = self.fields['h']

            else:
                # skip columns containing numeric values like UIDs, dates, IP addresses, SSNs, etc.
                # skip columns containing NULL
                skip_chars = ['0123456789-.:_ ']
                if not ( [all([char in string.digits for char in field]) for field in column].count(True)/len(lines) > self.threshold ) and \
                not ([field.upper() == 'NULL' for field in column].count(True)/len(lines) > self.threshold ):
                
                    unknown_fields.append(i)

            columns[i] = column

        return (columns, unknown_fields)



    def __iter__(self):

        #assert self.info_gathered, 'Run .gather_info() first'
        with open(str(self.file), 'rb') as f:
            for line in f:
                try:
                    yield self.translate_line(line)
                except AccountCreationError as e:
                    errprint('[!] {}: {}'.format(str(e), str(line)))
                    continue
