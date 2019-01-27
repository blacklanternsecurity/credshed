#!/usr/bin/env python3

from leak import *


class _2844(Leak):

    def __init__(self, source='2844', hashtype=''):

        super().__init__(source_name=source, source_hashtype=hashtype)

        


class LinkedIn(Leak):

    def __init__(self, source='linkedin', hashtype='SHA1'):

        super().__init__(source_name=source, source_hashtype=hashtype)

        # create hash:pass dictionary
        '''
        password_file = 'raw/{}/hashes.org-linkedin-97.92-percent.txt'.format(source)
        passwords = dict()

        print('[+] Reading {}'.format(password_file))

        with open(password_file) as f:
            for line in f:
                _hash, password = line.strip().split(':')[:2]
                passwords[_hash] = password

        #self.uid_passwords = dict()
        #self.uid_usernames = dict()
        '''

        '''
        for i in ['test@test.com', 'asdf@test.com', 'test@asdf.com', 'asdf@asdf.com']:
            self.add_account(email=i, password='Password1')
        '''

        self.files      = files # list of files containing data
        self.user_ids   = dict() # dictionary in format: id:username
        self.passwords  = dict() # dictionary in format: hash:password
        self.get_user_ids()
        self.get_password_hashes()

    '''
    def dump(self, directory):

        directory = Path(directory)
        assert directory.is_dir(), "{} doesn't appear to be a directory".format(directory)

        filename = directory / '{}-{}.txt'.format(self.source.name, self.source.hashtype)

        print('[+] Dumping to filename')

        with open(filename, 'w') as f:
            for account in self:
                f.write(str(account) + '\n')
    '''


    def read(self, files=['29.txt', '10.txt', '1_1.txt', '11.txt', '12.txt', '13.txt', '14.txt', '15.txt', '16.txt', '17.txt', '18.txt', '19.txt', '1.sql.txt', '1.txt', '20.txt', '2_1.txt', '21.txt', '22.txt', '23.txt', '24.txt', '25.txt', '26.txt', '27.txt', '28.txt', '2.txt', '30.txt', '3_1.txt', '31.txt', '32.txt', '33.txt', '34.txt', '35.txt', '36.txt', '37.txt', '3.txt', '4_1.txt', '4.txt', '5_1.txt', '5.txt', '6_1.txt', '6.txt', '7_1.txt', '7.txt', '8_1.txt', '8.txt', '9_1.txt', '9.txt']):

        try:

            errprint('[+]', end='')

            for file in self.files:

                if file not in ['1.sql.txt']:

                    errprint(' Processing file "{}"'.format(file))

                    Path(self.source.name).mkdir(mode=0o750, exist_ok=True)
                    with open('../raw/{}/{}'.format(self.source.name, file), 'rb') as f:
                        for line in f:

                            if file == '29.txt':
                                try:
                                    s = line.split()
                                    i = s.index(b'->')
                                    u = s[i+1]
                                    h = s[i-1]
                                except (ValueError, IndexError):
                                    continue

                            else:
                                u, h = line.split(b':')[:2]

                            u, h = u.strip(), h.strip()

                            # convert id to username
                            try:
                                u = self.user_ids[int(u)]
                            except ValueError:
                                pass
                            except KeyError:
                                continue

                            if not (u and h) or any([e in (b'null', b'xxx') for e in (u,h)]):
                                continue

                            # convert hash to password
                            try:
                                p = self.passwords[h]
                            except KeyError:
                                p = h

                            # weed out fake accounts (any account with a numeric password of length 15)
                            try:
                                if len(p) == 15:
                                    int(p)
                                    continue
                            except ValueError:
                                pass

                            # add a note if there's no password
                            if not p:
                                errprint('[*] Empty password for {}'.format(u.decode()))
                                m = b'Empty password'
                            else:
                                m = b''

                            self.add_account(email=u, password=p, misc=m)


        except KeyboardInterrupt:
            errprint('[*] Interrupted')



    def get_user_ids(self):

        # create id:username dictionary
        user_ids_file = Path('raw/{}/{}'.format(self.source.name, 'user_ids'))
        #user_ids_file = Path('/tmp/user_ids')
        if user_ids_file.exists():
            errprint('[+] Reading user IDs from {}'.format(user_ids_file.absolute()))

            with open(user_ids_file, 'rb') as f:
                c = 0
                for line in f:
                    try:
                        line = line.strip()
                        i,u = line.split(b':')[:2]
                        self.user_ids[int(i)] = u
                    except KeyError:
                        continue

                    if c % 1000 == 0:
                        errprint('\r[+] {:,}'.format(c), end='')
                    c += 1
            errprint('')

            

        else:
            for file in ['29.txt', '1.sql.txt']:

                filename = Path('../raw/{}/{}'.format(self.source.name, file))
                errprint('[+] Reading {}'.format(filename.absolute()))

                with open(filename, 'rb') as f:

                    for line in f:
                        line = line.strip()

                        if file == '1.sql.txt':
                            # INSERT INTO idemail VALUES ('59305718', 'shownuff00@yahoo.com');
                            try:
                                i,u = line.split(b"VALUES (")[1].split(b', ')
                                i = int(i.strip(b"'();"))
                                u = u.strip(b"'();")
                                self.user_ids[i] = u
                            except (IndexError,ValueError):
                                continue

                        elif file == '29.txt':
                            # 16143536 : 0932d7750ad638546788dbde939bb930e1934516 -> mindisgrishkus@yahoo.com
                            try:
                                i,u = line.split(b'->')[:2]
                                i = int(i.split(b':')[0].strip())
                                u = u.strip()
                                self.user_ids[i] = u
                            except (ValueError, KeyError):
                                continue

                        else:
                            # emilcecova@hotmail.com:1315ae6229444367968a943a219f38def9a8112d
                            # 8150255:3d4f2bf07dc1be38b20cd6e46949a1071f9d0e3d
                            continue

                errprint('[+] {:,} entries so far'.format(len(self.user_ids)))

            errprint('[+] Writing {:,} user IDs to {}'.format(len(self.user_ids), user_ids_file.absolute()))
            sleep(3)
            with open(user_ids_file, 'w') as f:
                for i in self.user_ids:
                    f.write(b'{}:{}\n'.format(i, self.user_ids[i]))


    def get_password_hashes(self):

        filename = Path('../raw/{}/hashes.org-linkedin-97.92-percent.txt'.format(self.source.name))
        #filename = Path('/tmp/hashes')
        errprint('[+] Reading hashes from {}'.format(filename.absolute()))

        with open(filename, 'rb') as f:
            c = 0
            for line in f:
                line = line.strip().split(b':')
                _hash = line[0]
                password = b':'.join(line[1:])
                self.passwords[_hash] = password

                if c % 1000 == 0:
                    errprint('\r[+] {:,}'.format(c), end='')
                c += 1
        errprint('')


if __name__ == '__main__':

    linkedin = LinkedIn()
    linkedin.read()
    linkedin.dump()