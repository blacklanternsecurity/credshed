# credshed
A full-featured solution for injesting, organizing, storing, and querying public leaks.  Injests gigantic files or entire directories with ease.

![credshed-gui-screenshot](https://user-images.githubusercontent.com/20261699/60697972-c059f900-9eb2-11e9-8a12-7db633c00eb0.png)
[credshed-gui web front-end](https://github.com/blacklanternsecurity/credshed)

## Usage
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
                        add file(s) to DB
  -t, --stats           show db stats
  -o OUT, --out OUT     write output to file instead of DB
  -d [SOURCE_ID [SOURCE_ID ...]], --delete-leak [SOURCE_ID [SOURCE_ID ...]]
                        delete leak(s) from DB, e.g. "1-3,5,7-9"
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
Database setup is completely automated with the `srv.sh` script located in `credshed/docker`
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
First, take a look at the settings in `srv.config`.
Choose the number of shards you want and the location of the database
~~~
$ cd credshed/docker
$ cat srv.config
srv_dir='/tmp/credshed/srv'

mongo_main_dir='/tmp/credshed/db/main'
mongo_meta_dir='/tmp/credshed/db/meta'
mongo_script_dir='/tmp/credshed/mongo_scripts'

num_shards=10
~~~
Once srv.config has been edited to your liking, execute this command to perform all the necessary setup.  Execution will take a couple of minutes and you will see a lot of output.  Note that after `prep` and `init` have been run, you only need to execute `start` and `stop` going forward.
~~~
$ ./srv.sh prep start init
~~~