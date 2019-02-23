#!/usr/bin/env python3.7

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

    def __init__(self, file, source_name=None, unattended=False, preformatted=False, threshold=.65, strict=True):

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
        self.threshold = threshold   # this percentage of lines must comply to detected format

        # gather information about source
        self.gather_source_info(file)

        self.strict = strict

        if not self.strict:
            self.info_gathered = True

        else:
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

            if preformatted:
                self.mapping[0] = self.fields['e']
                self.mapping[1] = self.fields['u']
                self.mapping[2] = self.fields['p']
                self.mapping[3] = self.fields['m']
                self.input_delimiter = b'\x00'
                self.num_input_fields = 4

            self.gather_info(skip_type_detection=preformatted)
        



    def gather_info(self, num_lines=5000, skip_type_detection=False):
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
        errprint('[+] Detected delimiter: {}'.format(str(self.input_delimiter)))

        # confirm delimiter if not unattended
        if not self.unattended:
            self._confirm_delimiter(all_lines)

        # get number of input fields, for ensuring that passwords
        # containing the delimiter character get parsed correctly
        try:
            split_lines = [self._split_line(line) for line in all_lines]
            self.num_input_fields = mode([len(split_line) for split_line in split_lines])
            #self.num_input_fields = mode([line.count(self.input_delimiter) for line in all_lines])
        except StatisticsError:
            self.num_input_fields = 0

        errprint('[+] {} fields detected'.format(self.num_input_fields))

        if self.num_input_fields < 2:
            if self.unattended:
                raise FieldDetectionError('not enough input fields detected')
            else:
                self.num_input_fields = input('How many fields? > ') or 2
                self.num_input_fields = int(self.num_input_fields)
            

        # detect what type of data is in each field
        # weed out the easy stuff (emails, hashes, blank columns)
        columns, unknown_fields = self._detect_fields(all_lines)

        if skip_type_detection:
            unknown_fields = []

        if unknown_fields:

            # try and figure the rest out
            if len(unknown_fields) == 1:
                errprint('[+] Assuming passwords in column #{}'.format(unknown_fields[0]+1))
                self.password_field = unknown_fields[0]
                self.mapping[unknown_fields[0]] = self.fields['p']
                unknown_fields = []

            elif len(unknown_fields) == 2:
                self.password_field = unknown_fields[1]
                errprint('[+] Assuming usernames in column #{}'.format(unknown_fields[0]+1))
                self.mapping[unknown_fields[0]] = self.fields['u']
                errprint('[+] Assuming passwords in column #{}'.format(unknown_fields[1]+1))
                self.mapping[unknown_fields[1]] = self.fields['p']
                unknown_fields = []

            elif self.unattended:
                # die alone, in the dark
                raise FieldDetectionError('Unknown column in {}'.format(self.file))


        # ask for help
        while not self.info_gathered == True:
            for i in unknown_fields:
                column = columns[i]
                if all([field == '' for field in column]):
                    errprint('[+] Skipping blank column')
                    continue

                sample_len = 20
                for f in random.sample(column, len(column)):
                    if f:
                        errprint('  {}'.format(f))
                        sample_len -= 1
                    if sample_len <= 0:
                        break

                #errprint('  ' + '\n  '.join(random.sample(column, 20)))

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
                    raise FieldDetectionError('Unknown column in {}'.format(self.file))
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
                    #errprint('[!] {}: {}'.format(str(e), str(line)))
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
                for in_index in self.mapping:
                    for i in self.fields.items():
                        if self.mapping[in_index] == i[1]:
                            print('Column #{} -> {}'.format(in_index+1, i[0]))
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


    def _split_line(self, line, delimiter=None):

        if delimiter is None:
            delimiter = self.input_delimiter

        # handle the classic "semicolon instead of colon" problem
        for i in range(len(line)):
            char = line[i:i+1]
            if char == delimiter:
                break
            # if semicolon is found before delimiter, replace it
            elif char == b';':
                line = line.replace(b';', delimiter, self.num_input_fields-1)
                break

        return line.strip(b'\r\n').split(delimiter)



    def translate_line(self, line):
        '''
        converts each line to an Account() object
        '''

        line_old = self._split_line(line)
        len_diff = len(line) - self.num_input_fields
        line_new = [b''] * 5

        for p in self.mapping:
            try:
                if len_diff and p == self.password_field:
                    # handle edge case where password contains delimiter character
                    line_new[self.mapping[p]] = self.input_delimiter.join(line_old[p:p+len_diff+1])
                else:
                    line_new[self.mapping[p]] = line_old[p]
            except IndexError:
                raise AccountCreationError('Index {} does not exist in {}'.format(p, str(line)[:128]))

        else:
            email, username, password, _hash, misc = line_new
            return Account(email, username, password, _hash, misc)



    def absorb_line(self, line):
        '''
        less-strict function that takes a line and looks for an email address
        the rest of the line is placed in the "misc" field of the account
        '''

        email_match = Account.email_regex_search_bytes.search(line)

        if email_match:
            email = line[email_match.start():email_match.end()]

            # strip out email and replace with "@"
            # only use the last 255 characters
            return Account(email=email, misc=line.replace(email, b'@')[-255:])

        else:
            raise AccountCreationError('No valid email in line: {}'.format(str(line)[:128]))




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
                if not (char.isalnum() or char in [b'@', b'.', b'!', b'?', b'(', b')', b'-', b'_']):

                    # hackers are silly bois
                    # so we just pretend all semicolons are colons
                    if char == b';':
                        char = b':'

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
                ties = [ s for s in consistency_scores if s[1][0] == d0[1][0] and s[1][1] == d0[1][1] ]

                if len(ties) > 1:
                    ties_str = b'" "'.join([s[0] for s in ties])
                    raise DelimiterError('Multiple delimiter candidates: "{}" in file "{}"'.format(str(ties_str)[2:-1], self.file))

            # make sure most lines fit the detected format
            valid_lines = score / len(lines)
            if valid_lines < self.threshold:
                raise DelimiterError('Delimiter "{}"" ({:1f}%) failed threshold ({:.1f}%) in "{}"'.format(\
                    str(d0[0])[2:-1], (valid_lines*100), self.threshold, self.file))

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
                    field = self._split_line(line)[i]
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
            num_emails = [Account.is_fuzzy_email(field) for field in column].count(True)
            if num_emails > int(.75 * len(lines)) and not self.fields['e'] in self.mapping.values():
                errprint('[+] Detected emails in column #{}'.format(i+1))
                self.mapping[i] = self.fields['e']

            # detect hashes
            # all non-blank fields in column must be the same length
            # and be at least 12 characters in length
            # and contain only hex characters
            elif random_field_length >= 12 and \
                [len(field) == random_field_length for field in column_no_blanks].count(True)/len(column_no_blanks) > self.threshold and \
                [all([char.lower() in 'abcdef0123456789' for char in field]) for field in column_no_blanks].count(True)/len(column_no_blanks) > self.threshold:
                    errprint('[+] Detected hashes in column #{}'.format(i+1))
                    self.mapping[i] = self.fields['h']

            else:
                # skip columns containing numeric values like UIDs, dates, IP addresses, SSNs, etc.
                # skip columns containing NULL
                skip_chars = ['0123456789-.:_ ']
                if ( [all([char in string.digits for char in field]) for field in column].count(True)/len(lines) > self.threshold ) and \
                not ([field.upper() == 'NULL' for field in column].count(True)/len(lines) > self.threshold ):
                    errprint('[+] Skipping numeric field')
                else:
                    unknown_fields.append(i)

            columns[i] = column

        return (columns, unknown_fields)



    def __iter__(self):

        #assert self.info_gathered, 'Run .gather_info() first'
        with open(str(self.file), 'rb') as f:
            for line in f:
                try:
                    if self.strict:
                        yield self.translate_line(line)
                    else:
                        yield self.absorb_line(line)
                except AccountCreationError as e:
                    errprint('[!] {}: {}'.format(str(e)[:128], str(line)[:128]))
                    continue