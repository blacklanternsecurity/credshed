# c r e d s h e d
A full-featured solution for injesting, organizing, storing, and querying public credential leaks.  Injests gigantic files or entire directories with ease.  (It will find every email address in your `/etc` directory if you tell it to!)
Includes native Pastebin-scraping functionality.

![credshed-gui-screenshot](https://user-images.githubusercontent.com/20261699/67125567-1d0fc400-f1c3-11e9-850c-b3baa620e791.png)

Pastebin Scraper Report

## CLI Usage
~~~
$ ./credshed-cli.py --help
usage: credshed-cli.py [-h] [-q QUERY_TYPE] [-i INGEST [INGEST ...]] [-f] [-db] [-s] [-d [SOURCE_ID [SOURCE_ID ...]]] [-dd] [--drop] [--threads THREADS] [--print0] [--limit LIMIT] [-u] [-v] [--debug] [search [search ...]]

positional arguments:
  search                search term(s)

optional arguments:
  -h, --help            show this help message and exit
  -q QUERY_TYPE, --query-type QUERY_TYPE
                        query type (email, domain, or username)
  -i INGEST [INGEST ...], --ingest INGEST [INGEST ...]
                        import files or directories into the database
  -f, --force-ingest    also ingest files which have already been imported
  -db, --db-stats       show all imported leaks and DB stats
  -s, --stdout          when importing, write to stdout instead of database (null-byte delimited, use tr '\0')
  -d [SOURCE_ID [SOURCE_ID ...]], --delete-leak [SOURCE_ID [SOURCE_ID ...]]
                        delete leak(s) from database, e.g. "1-3,5,7-9"
  -dd, --deduplication  deduplicate accounts ahead of time by loading them into memory
  --drop                delete the entire database D:
  --threads THREADS     number of threads for import operations
  --print0              delimit search results by null byte instead of colon
  --limit LIMIT         limit number of results (default: unlimited)
  -u, --unattended      auto-detect import fields without user interaction
  -v, --verbose         show what is happening
  --debug               display detailed debugging info
~~~

## Setup
Credshed uses mongodb to store data.  Setup can be as simple as `docker run -p 27017 mongo`, although I highly recommend using `deploy/docker-compose.yml`, which contains optimizations for heavy write loads.
1. Create a directory where you'd like to store the data, and chmod it to UID 999 (the default mongodb user)
~~~
$ mkdir /data
$ chown 999:999 /data
~~~
2. Edit `deploy/docker-compose.yml` and ensure the volume is pointing to the new data directory you just created.  And for the love of heaven, pick a secure password.
3. Bring up the mongodb service
~~~
$ cd deploy
$ docker-compose up
~~~
4. Place the same password in `credshed.config` and make sure the host and port matches your database configuration
6. Verify the config is valid by searching the database (it will be empty at this point, that's fine)
~~~
$ ./credshed-cli.py test@example.com
~~~
7. (Optional) Set the database to start automatically:
  - First, stop the database
  - Edit `WorkingDirectory` in `deploy/credshed.service` to match the directory where it is installed
  - Install, enable, and start the credshed systemd service
~~~
$ sudo cp credshed/docker/credshed.service /etc/systemd/system/
$ sudo systemctl enable credshed.service --now
# check on its status
$ journalctl -xefu credshed.service
~~~
8. (Optional) If you want to enable logging, create the directory `/var/log/credshed` and make sure whichever user is running `credshed-cli.py` has write access


## Example 1: Extract all compressed files
Credshed will locate every compressed file, determine its format (e.g. zip, gzip, 7zip, etc.), and attempt to extract it.  This includes converting XLSX files to CSV
~~~
# It's a good idea to run this a few times until all possible archives are extracted.
$ ./filestore-cli.py ./filestore-cli.py --extract --delete /mnt/leaks
~~~

## Example 2: Load files (or directories) into database
Search for emails in every file and import into the database.  Credshed will automatically determine the encoding of each file.  It detects and handles emails, hashes, and even SQL statements.
~~~
$ ./credshed-cli.py --unattended --ingest /mnt/leaks
~~~