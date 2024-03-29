# by TheTechromancer

import random
import string
import logging
from ..errors import *
from .file import File
from time import sleep
from ..account import *
from .. import validation
from pathlib import Path, PosixPath
from statistics import mode, StatisticsError


# set up logging
log = logging.getLogger('credshed.textparser')


class TextParse():
    '''
    takes a filename
    yields Account() objects

    By default, it tries to detect delimiter & fields
    If that fails, it throws a TextParseError
    Running with strict=False disables these checks
    '''

    def __init__(self, file, unattended=False, strict=True, threshold=.80, force_ascii=False):

        self.output_delimiter = '\x00'
        self.input_delimiter = ':'
        self.num_input_fields = 2       # number of input fields, for edge case where password contains delimiter character
        self.password_field = 1         # used in combination with num_input_fields
        self.unattended = unattended    # whether to parse files automatically
        self.strict = True              # whether to detect individual columns or just straight absorb
        self.threshold = threshold      # this percentage of lines must comply to detected format
        self.force_ascii = force_ascii  # skip encoding detection and just use ascii

        # check if 'file' is of type Path
        try:
            file.resolve()
            self.file = file
        except AttributeError:
            self.file = File(file, force_ascii=self.force_ascii)


        # whether the columns have been mapped to fields (e.g. email, username, etc.)
        self.columns_mapped = False

        # email:username:password:hash:misc
        self.fields = {
            'e': 0, # email
            'u': 1, # username
            'p': 2, # password
            'h': 3, # hash
            'm': 4  # misc
        }

        # input_position --> output_position
        self.mapping = dict()

        if strict or not unattended:
            self.gather_info()
            



    def gather_info(self, num_lines=5000, skip_type_detection=False):
        '''
        gather information about how to parse the file
        such as delimiter, field order, etc.
        '''

        # make sure file exists
        if not self.file.is_file():
            raise TextParseError(f'Failure reading {self.file}')

        head = self._head(str(self.file), num_lines=int(num_lines*2))

        # skip the first num_lines and start somewhere in the middle of the file
        # this avoids problems in large files which are sorted with symbols first
        # and have a bunch of junk at the beginning
        all_lines = head[-num_lines:]
        if not all_lines:
            raise TextParseError(f'Error reading (or empty) file: {self.file}')

        self.input_delimiter = self._get_delimiter(all_lines)
        detected_delimiter = self.input_delimiter.__repr__().strip("'")
        log.info(f'Detected delimiter: {detected_delimiter}')

        # confirm delimiter if not unattended
        if not self.unattended:
            self._confirm_delimiter(all_lines)

        # get number of input fields, for ensuring that passwords
        # containing the delimiter character get parsed correctly
        try:
            split_lines = [self._split_line(line, all=True) for line in all_lines]
            self.num_input_fields = mode([len(split_line) for split_line in split_lines])
            #self.num_input_fields = mode([line.count(self.input_delimiter) for line in all_lines])
        except StatisticsError:
            self.num_input_fields = 0

        log.info(f'{self.num_input_fields:,} fields detected')

        if self.num_input_fields < 2:
            if self.unattended:
                raise FieldDetectionError('not enough input fields detected')
            else:
                self.num_input_fields = input('How many fields? > ') or 2
                self.num_input_fields = int(self.num_input_fields)

        # check if file was generated by credshed
        elif self.num_input_fields == 5 and self.input_delimiter == '\x00':
            skip_type_detection = True

            self.mapping[0] = self.fields['e']
            self.mapping[1] = self.fields['u']
            self.mapping[2] = self.fields['p']
            self.mapping[3] = self.fields['h']
            self.mapping[4] = self.fields['m']

        # detect what type of data is in each field
        # weed out the easy stuff (emails, hashes, blank columns)
        columns, unknown_fields = self._detect_fields(all_lines)

        if skip_type_detection:
            unknown_fields = []

        # if there are unknown fields, try and figure the rest out
        if unknown_fields:

            # if there's only one unknown field
            if len(unknown_fields) == 1:
            
                # assume passwords if we already have username or email
                if any([x in self.mapping.values() for x in [self.fields['e'], self.fields['u']]]):
                    log.info(f'Assuming passwords in column #{unknown_fields[0]+1}')
                    self.password_field = unknown_fields[0]
                    self.mapping[unknown_fields[0]] = self.fields['p']
                    unknown_fields = []

                # assume usernames if we already have hashes or passwords
                elif any([x in self.mapping.values() for x in [self.fields['h'], self.fields['p']]]):
                    log.info(f'Assuming usernames in column #{unknown_fields[0]+1}')
                    self.mapping[unknown_fields[0]] = self.fields['u']
                    unknown_fields = []

            elif not self.unattended:
                # if we haven't mapped email or usernames yet, and there's two unknown fields
                # assume usernames and passwords
                if len(unknown_fields) == 2 and not any([x in self.mapping.values() for x in [self.fields['e'], self.fields['u']]]):
                    self.password_field = unknown_fields[1]
                    log.info(f'Assuming usernames in column #{unknown_fields[0]+1}')
                    self.mapping[unknown_fields[0]] = self.fields['u']
                    log.info(f'Assuming passwords in column #{unknown_fields[1]+1}')
                    self.mapping[unknown_fields[1]] = self.fields['p']
                    unknown_fields = []


            if self.unattended and unknown_fields:
                # die alone, in the dark
                raise FieldDetectionError(f'Unknown column in {self.file}')


        # ask for help
        while not self.columns_mapped == True:
            for i in unknown_fields:
                column = columns[i]
                if all([field == '' for field in column]):
                    log.info('Skipping blank column')
                    continue

                sample_len = 20
                for f in random.sample(column, len(column)):
                    if f:
                        log.info(f'  {f}')
                        sample_len -= 1
                    if sample_len <= 0:
                        break

                #self._adaptive_print('  ' + '\n  '.join(random.sample(column, 20)))

                # assume last field is password if email/username is already mapped
                #if auto:
                #    id_mapped = any([f in self.mapping.values() for f in (self.fields['u'], self.fields['e'])])
                #    last_column = all([all([f == '' for f in c]) for c in columns[i+1:]])
                #    # print('[+] id_mapped: {}, last_column: {}'.format(id_mapped, last_column))
                #    if id_mapped and last_column:

                #        self.password_field = i
                #        self.mapping[i] = self.fields['p']
                #        self.columns_mapped = True
                #        break

                if self.unattended:
                    raise FieldDetectionError(f'Unknown column in {self.file}')

                # otherwise, ask user
                log.warning('=' * 60)
                log.warning('[?] Which column is this?')
                log.warning('=' * 60)
                sleep(.2)
                field = input('[-] [E]mail | [U]ser | [P]assword | [H]ash | [M]isc | [enter] to skip > ').strip().lower()
                if any([field.startswith(f) for f in self.fields.keys()]):
                    self.mapping[i] = self.fields[field[0]]
                    if field == 'p':
                        self.password_field = i
                elif not field:
                    log.warning('Skipped')
                    continue
                else:
                    log.warning('Please try again')
                    sleep(1)

            # must have at least two fields
            if not (any([i in self.mapping.values() for i in (self.fields['u'], self.fields['e'])]) and \
                any([i in self.mapping.values() for i in (self.fields['p'], self.fields['h'], self.fields['m'])])):
                #raise ValueError('Not enough fields mapped in {}'.format(file))
                log.error('Not enough fields mapped')
                self.mapping.clear()
                unknown_fields = list(range(self.num_input_fields))
                continue

            translated_lines = []
            for line in all_lines:
                try:
                    for account in self.translate_line(line):
                        translated_lines.append(str(account))
                except AccountCreationError as e:
                    log.debug(str(e))
                    continue

            # display and confirm selection
            log.info(('=' * 60))
            log.info('email:username:password:hash:misc/description')
            log.info('=' * 60)
            for _ in range(min(20, len(translated_lines))):
                line = random.choice(translated_lines)
                translated_lines.remove(line)
                #try:
                log.info(' ' + line)
                #    #self._adaptive_print(line.decode().replace(self.output_delimiter.decode(), ':'))
                #except UnicodeDecodeError:
                #    continue
            log.info('=' * 60)

            positions_taken = set()
            for in_index in self.mapping:
                for fieldname, position in self.fields.items():
                    if self.mapping[in_index] == position:
                        if position not in positions_taken:
                            log.info(f'Column #{in_index+1} -> {fieldname}')
                            positions_taken.add(position)

            if self.unattended:
                log.info(f'Unattended parsing of {self.file} was successful')
                self.columns_mapped = True
            else:
                sleep(.2)
                if not input('\n[-] OK? [Y/n] ').lower().startswith('n'):
                    self.columns_mapped = True
                else:
                    self.mapping.clear()
                    unknown_fields = list(range(self.num_input_fields))


    def _split_line(self, line, delimiter=None, all=False):

        if delimiter is None:
            delimiter = self.input_delimiter

        if all:
            return line.split(delimiter)
        else:
            return line.split(delimiter, self.num_input_fields-1)



    def translate_line(self, line):
        '''
        polite and picky function which takes a line and maps its fields exactly as declared in self.mapping
        yields Account() objects
        '''

        #log.debug(f'TRANSLATING {line}')

        try:

            line_old = self._split_line(line)
            #len_diff = len(line) - self.num_input_fields
            line_new = [''] * 5

            for p in self.mapping:
                try:
                    #if len_diff and p == self.password_field:
                    #    # handle edge case where password contains delimiter character
                    #    line_new[self.mapping[p]] = self.input_delimiter.join(line_old[p:p+len_diff+1])
                    #else:
                    line_new[self.mapping[p]] = line_old[p]
                except IndexError:
                    raise AccountCreationError(f'Index {p} does not exist in {str(line)[:80]}')


            email, username, password, _hash, misc = line_new
            yield Account(email, username, password, _hash, misc)

        except AccountCreationError as e:
            for account in self.absorb_line(line):
                yield account



    def absorb_line(self, line):
        '''
        takes a line and looks for email addresses and hashes
        each email is extracted along with the surrounding text, which is placed into the "misc" field
        the misc section is then searched for a hash
        yields Account() objects
        '''

        #log.debug(f'ABSORBING {line}')

        # try the common email:password format
        try:
            try:
                # try colon
                email, password = line.split(':')
            except ValueError:
                # try semicolon
                email, password = line.split(';')

            yield Account(email=email, password=password)

        # if that fails, ABSORB
        except (ValueError, AccountCreationError) as e:
            #log.debug(str(e))

            # find every matching email in the line
            email_matches = [(0,0)] + [m.span() for m in validation.email_regex_search.finditer(line)] + [(len(line),0)]

            # for each match
            for i in range(1, len(email_matches)-1):

                # find where the current email starts and ends
                startpos,endpos = email_matches[i]
                email = line[startpos:endpos]

                # find where the previous email ends
                context_start = email_matches[i-1][-1]
                # find where the next email starts
                context_end = email_matches[i+1][0]
                # limit to 1000 characters
                left_side = line[context_start:startpos][-500:]
                extra_chars = 500-len(left_side)
                right_side = line[endpos:context_end][:500+extra_chars]

                if len(left_side) > 1 or len(right_side) > 1:

                    misc = left_side + '@' + right_side

                    # look for hashes
                    found_hashes = list(validation.find_hashes(misc))
                    # shortest hashes come first
                    found_hashes.sort(key=lambda x: len(x))
                    if found_hashes:
                        for h in found_hashes:
                            misc = misc.replace(h, '#')
                        if len(misc) <= 2:
                            misc = ''

                    # strip out other email addresses
                    misc = validation.strip_emails(misc)

                    yield Account(email=email, hashes=found_hashes, misc=misc)

                else:
                    yield Account(email=email)




    def _get_delimiter(self, lines):
        '''
        delimiter is the non-alphanumeric character with the most consistent per-line count
        '''
        excluded_delimiters = ('@', '.', '!', '?', '(', ')', '-', '_', '/', '"', "'", '[', ']', '{', '}', '=', '<', '>')

        per_line_char_counts = dict()
        # count number of special characters for each line
        for i in range(len(lines)):
            line = lines[i]
            for j in range(len(line)):
                char = line[j:j+1]
                if not (char.isalnum() or char in excluded_delimiters):

                    # hackers are silly bois
                    # so we just pretend all semicolons are colons
                    if char == ';':
                        char = ':'

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
            raise DelimiterError(f'No delimiter candidates found in file "{self.file}"')

        # do some additional checks if unattended
        if self.unattended:
            d0 = consistency_scores[0]
            if len(consistency_scores) > 1:

                # handle a tie
                ties = [ s for s in consistency_scores if s[1][0] == d0[1][0] and s[1][1] == d0[1][1] ]

                if len(ties) > 1:
                    ties_str = '" "'.join([s[0] for s in ties])
                    raise DelimiterError(f'Multiple delimiter candidates: "{str(ties_str)[2:-1]}" in file "{self.file}"')

            # make sure most lines fit the detected format
            valid_lines = score / len(lines)
            if valid_lines < self.threshold:
                raise DelimiterError('Delimiter "{}" ({:.1f}%) failed threshold ({:.1f}%) in "{}"'.format(\
                    str(d0[0])[2:-1], (valid_lines*100), self.threshold*100, self.file))

        return best_delimiter



    def _confirm_delimiter(self, lines):

        # print 20 random lines
        l = [_ for _ in lines]
        log.warning('=' * 60)
        for _ in range(min(20, len(lines))):
            rand_choice = random.choice(l)
            l.remove(rand_choice)
            log.warning(' ' + str(rand_choice)[2:-1])
        log.warning('=' * 60)
        sleep(.2)
        detected_delimiter = self.input_delimiter.__repr__().strip("'")
        self.input_delimiter = input(f'[-] Delimiter [{detected_delimiter}] > ') or self.input_delimiter

        # handle case where delimiter is hexidecimal
        hex_prefixes = ['\\x', '0x']
        new_delimiter = []
        if any([x in self.input_delimiter for x in hex_prefixes]):
            i = 0
            for _ in range(len(self.input_delimiter)):
                if self.input_delimiter[i:i+2] in hex_prefixes:
                    hex_chunk = self.input_delimiter[i+2:i+4]
                    try:
                        new_delimiter.append(bytes.fromhex(hex_chunk).decode())
                        i += 4
                        continue
                    except ValueError:
                        pass

                new_delimiter.append(self.input_delimiter[i:i+1])
                i += 1

            self.input_delimiter = ''.join(new_delimiter)

        log.info(f'Using delimiter: {self.input_delimiter}')



    def _detect_fields(self, lines):

        unknown_fields = []
        columns = [[] for i in range(self.num_input_fields)]
        for i in range(self.num_input_fields):
            
            # build column
            column = []
            for line in lines:
                try:
                    field = self._split_line(line, all=True)[i]
                    field = field
                    column.append(field)
                except IndexError:
                    column.append('')


            column_no_blanks = [f for f in column if f]
            if column_no_blanks:
                # take a field length from somewhere in the middle
                random_field_length = len(column_no_blanks[int(len(column_no_blanks)/2)])
            else:
                # skip blank columns
                continue

            # detect emails
            num_emails = [validation.is_fuzzy_email(field) for field in column].count(True)
            if (num_emails / len(lines) > self.threshold) and not self.fields['e'] in self.mapping.values():
                log.info(f'Detected emails in column #{i+1}')
                self.mapping[i] = self.fields['e']

            else:
                # skip columns containing numeric values like UIDs, dates, IP addresses, SSNs, etc.
                # skip columns containing NULL
                skip_chars = ['0123456789-.:_/ \t']
                if ( [all([char in string.digits for char in field]) for field in column].count(True)/len(lines) > self.threshold ) and \
                not ([field.upper() == 'NULL' for field in column].count(True)/len(lines) > self.threshold ):
                    log.info('Skipping numeric field')

                # detect hashes
                # all non-blank fields in column must be the same length
                # and be at least 12 characters in length
                # and contain only hex characters
                elif random_field_length >= 12 and \
                    [len(field) == random_field_length for field in column_no_blanks].count(True)/len(column_no_blanks) > self.threshold and \
                    [validation.is_hash(field) for field in column_no_blanks].count(True)/len(column_no_blanks) > self.threshold:
                        log.info(f'Detected hashes in column #{i+1}')
                        self.mapping[i] = self.fields['h']

                else:
                    unknown_fields.append(i)

            columns[i] = column

        return (columns, unknown_fields)



    def _head(self, filename, num_lines=10):

        lines = []

        try:
            for line in File(filename, parse=False):
                lines.append(line[:1024])
                num_lines -= 1
                if num_lines <= 0:
                    break

        except OSError as e:
            log.error(e)
            pass

        finally:
            return lines



    def __iter__(self):

        for line in self.file:
            try:
                if self.strict:
                    for account in self.translate_line(line):
                        yield account
                else:
                    for account in self.absorb_line(line):
                        yield account

            except LineAbsorptionError:
                continue

            except AccountCreationError as e:
                # log.warning(str(e))
                continue