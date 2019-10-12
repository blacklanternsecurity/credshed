# c r e d s h e d
A full-featured solution for injesting, organizing, storing, and querying public credential leaks.  Injests gigantic files or entire directories with ease.  (For funzies, try giving it your `/etc` directory and watch it pull out every single email address!)
Includes native Pastebin-scraping functionality!

![credshed-gui-screenshot](https://user-images.githubusercontent.com/20261699/60762868-33d44580-a02e-11e9-8294-200c711328f5.png)
[credshed-gui web front-end](https://github.com/blacklanternsecurity/credshed-gui)

## CLI Usage
~~~
$ ./credshed-cli.py --help
usage: credshed-cli.py [-h] [-q QUERY_TYPE] [-a ADD [ADD ...]] [-t] [-o OUT]
                       [-d [SOURCE_ID [SOURCE_ID ...]]] [-dd] [-p] [-m]
                       [--threads THREADS] [-u] [--no-metadata]
                       [--metadata-only] [-v]
                       [search [search ...]]

positional arguments:
  search                search term(s)

optional arguments:
  -h, --help            show this help message and exit
  -q QUERY_TYPE, --query-type QUERY_TYPE
                        query type (email, domain, or username)
  -a ADD [ADD ...], --add ADD [ADD ...]
                        add files or directories to the database
  -t, --stats           show db stats
  -o OUT, --out OUT     write output to file instead of database
  -d [SOURCE_ID [SOURCE_ID ...]], --delete-leak [SOURCE_ID [SOURCE_ID ...]]
                        delete leak(s) from database, e.g. "1-3,5,7-9"
  -dd, --deduplication  deduplicate accounts ahead of time (may eat memory)
  -p, --search-passwords
                        search by password
  -m, --search-description
                        search by description / misc
  --threads THREADS     number of threads for import operations
  -u, --unattended      auto-detect import fields without user interaction
  --no-metadata         disable metadata database
  --metadata-only       when importing, only import metadata
  -v, --verbose         display all available data for each account
~~~

## Setup
Database setup is almost entirely automated with the `srv.sh` script located in `credshed/docker`
~~~
$ ./srv.sh --help
Usage: srv.sh [option]

  Options:

    [1] prep    create docker-compose.yml & init scripts
    [2] start   start containers
    [3] init    initialize mongodb shards
        stop    stop dockerd
        clean   remove artifacts such as docker containers & images
        delete  delete entire database
~~~

1. If you intend to start the database automatically, you need the following in `/etc/docker/daemon.json`:
~~~
{
    "userns-remap": "default"
}
~~~
This remaps "root" inside the MongoDB containers to a higher UID/GID with no local privileges.

2. Take a look at the settings in `credshed/docker/srv.config`
  - Choose the number of shards you want and the location of the database
  - And for the love of geebus, change the password
~~~
$ cd credshed/docker
$ cat srv.config
num_shards=4

mongo_main_dir='/tmp/credshed/db/main'
mongo_meta_dir='/tmp/credshed/db/meta'
mongo_script_dir='/tmp/credshed/mongo_scripts'
mongo_user=root
mongo_pass=INTHENAMEOFALLTHATISHOLYPLEASECHANGETHIS
~~~
3. Once `srv.config` has been edited to your liking, execute this command to perform all the necessary setup.  Execution will take a couple of minutes and you will see a lot of output.  Note that after `prep` and `init` have been run, you only need to execute `start` and `stop` going forward.
~~~
$ ./srv.sh prep start init
~~~
4. Delete `srv.config` (or remove the password) as it is no longer needed
5. Take a look at `credshed.config`
  - Change the password to the same one as before
  - Fill out the appropriate server and port settings
~~~
# required
[MONGO PRIMARY]
server=127.0.0.1
port=27000
db=credshed

# not required
[MONGO METADATA]
server=127.0.0.1
port=27001
db=credshed

[GLOBAL]
# username and password are applied to both instances
user=root
pass=INTHENAMEOFALLTHATISHOLYPLEASECHANGETHIS
~~~
6. Take it for a test run
~~~
$ ./credshed-cli.py test@example.com
~~~
7. (Optional) Set the database to start automatically:
  - First stop any running instances
  - Edit `WorkingDirectory` in `credshed/docker/credshed.service` to match the directory where it is installed
  - Install, enable, and start the credshed systemd service
~~~
$ sudo cp credshed/docker/credshed.service /etc/systemd/system/
$ sudo systemctl enable credshed.service --now
# check on its status
$ journalctl -xefu credshed.service
~~~
8. (Optional) If you want to enable logging, create the directory `/var/log/credshed` and make sure whichever user is running `credshed-cli.py` has write access
9. (Optional) Set up Pastebin scraping
  - Visit https://pastebin.com/doc_scraping_api and whitelist your IP address. (the scraping code does not need your API key)
  - Run the script to make sure it works
~~~
$ ./pastebin-scaper.py
INFO] Retrieving 100 newest pastes
[DEBUG] Fetching https://scrape.pastebin.com/api_scrape_item.php?i=1a2b3c4d
...
~~~
  - Edit `WorkingDirectory` in `credshed/docker/pastebin-scraper.service` to match the directory where it is installed
  - Change `User` in `credshed/docker/pastebin-scraper.service` to a low-privileged user (for security)
  - Install, enable, and start the pastebin-scraper systemd service
~~~
$ sudo cp credshed/docker/pastebin-scraper.service /etc/systemd/system/
$ sudo systemctl enable pastebin-scraper.service --now
# check on its status
$ journalctl -xefu pastebin-scraper.service
~~~
  - NOTE: interesting pastes will also be saved to the current working directory unless the `--dont-save` option is specified

## Pastebin Scraper Usage
~~~
$ ./pastebin-scraper.py --help
usage: pastebin-scraper.py [-h] [-d LOOP_DELAY] [-s SCRAPE_LIMIT]
                           [--save-dir SAVE_DIR] [--dont-save] [--no-metadata]
                           [--metadata-only]

optional arguments:
  -h, --help            show this help message and exit
  -d LOOP_DELAY, --loop-delay LOOP_DELAY
                        seconds between API queries (default 60)
  -s SCRAPE_LIMIT, --scrape-limit SCRAPE_LIMIT
                        max pastes to scrape at once (default 100)
  --save-dir SAVE_DIR   save pastes as files here (default
                        /opt/credshed)
  --dont-save           don't write pastes to file
  --no-metadata         disable metadata database
  --metadata-only       when importing, only import metadata
~~~