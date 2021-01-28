#!/bin/bash

# by TheTechromancer

. ./srv.config

usage()
{
    cat <<EOF
Usage: ${0##*/} [option]

  Options:

    [1] prep    create docker-compose.yml & init scripts
    [2] start   start containers
    [3] init    initialize mongodb shards
        stop    stop containers
        clean   remove artifacts such as docker containers & images
        delete  delete entire database
        rebuild alias for "stop delete prep start init"
        reset   delete database contents & reinsert test data

EOF
exit 0
}



start_daemon()
{

    # cache sudo privileges to prevent script from dying
    sudo echo -n ''

    if ! pgrep dockerd >/dev/null
    then
        printf '[+] Starting daemon\n'
        sudo systemctl start docker

        for i in $(seq 60)
        do
            docker ps >/dev/null 2>&1 && break
            if [[ $i -eq 5 ]]
            then
                printf '[!] Failed to start daemon\n'
                exit 1
            fi
            sleep .5
        done

        printf '[+] Daemon successfully started\n'

    fi

    sleep 1

}


start_containers()
{

    sudo docker-compose up -d

}


stop_containers()
{

    sudo docker-compose down

}


clean()
{

    start_daemon
    sudo docker-compose rm
    sudo docker image prune -f
    sudo docker network prune -f
    # sudo rm /etc/subgid /etc/subuid >/dev/null 2>&1

    # create_dirs_and_yaml

}


delete_db()
{
    to_delete=( "$db_dir" "$script_dir" )

    printf '\n[!] DELETING THESE DIRECTORIES - PRESS CTRL+C TO CANCEL\n\n'
    for _dir in "${to_delete[@]}"; do
        if [ -d "$_dir" ]
        then
            printf "$_dir\n"
        fi
    done
    printf '\n'

    sleep 5

    for _dir in "${to_delete[@]}"; do
        if [ -d "$_dir" ]
        then
            sudo rm -r "$_dir"
        fi
    done

    # create_dirs_and_yaml
    printf '[+] Done.\n'

}


create_dirs_and_yaml()
{

    sudo rm docker-compose.yml
    touch docker-compose.yml

    echo "version: '3'

services:" | tee -a docker-compose.yml | fgrep -v MONGO_INITDB_ROOT

    # create YAML for primary router
    echo "
    router:
        image: mongo
        command: mongos --keyFile /scripts/mongodb.key --port 27017 --configdb configserver/config0:27017 --bind_ip_all #--setParameter taskExecutorPoolSize=0 --setParameter ShardingTaskExecutorPoolMinSize=10 --setParameter ShardingTaskExecutorPoolMaxConnecting=50 
        ports:
            - \"172.17.0.1:27017:27017\"
        volumes:
            - ${script_dir}:/scripts
        ulimits:
            nproc: 64000
            nofile: 64000
            memlock: -1
            fsize: -1
            cpu: -1
            as: -1
        logging:
            options:
                max-size: 500m
                max-file: 3
        depends_on:
            - config0" | tee -a docker-compose.yml
    for shard in $(seq 1 $num_shards)
    do
        echo "            - shard${shard}a" | tee -a docker-compose.yml
    done
    echo "        networks:
            - mongo" | tee -a docker-compose.yml

    # create YAML for primary config server
    echo "
    config0:
        image: mongo
        command: mongod --keyFile /scripts/mongodb.key --port 27017 --configsvr --replSet configserver --bind_ip_all
        volumes:
            - ${script_dir}:/scripts
            - ${db_dir}/mongo_config_0:/data/configdb:delegated
        environment:
            - MONGO_INITDB_ROOT_USERNAME=${mongo_user}
            - MONGO_INITDB_ROOT_PASSWORD=${mongo_pass}
        ulimits:
            nproc: 64000
            nofile: 64000
            memlock: -1
            fsize: -1
            cpu: -1
            as: -1
        logging:
            options:
                max-size: 500m
                max-file: 3
        networks:
            - mongo" | tee -a docker-compose.yml

    # create parent directory for primary config server
    sudo mkdir -p "${db_dir}/mongo_config_0" 2>/dev/null
    sudo chown 999:999 "${db_dir}/mongo_config_0"
    sudo mkdir -p "${db_dir}/mongo_config_1" 2>/dev/null
    sudo chown 999:999 "${db_dir}/mongo_config_1"
    #sudo chmod 777 "${db_dir}/mongo_config_0"

    # create directories & containers for primary database shards
    for shard in $(seq 1 $num_shards)
    do
        dir_name="${db_dir}/mongo_shard_${shard}a"
        if [ -n "$dir_name" -a ! -d "$dir_name" ]
        then
            sudo mkdir -p "$dir_name" 2>/dev/null
            sudo chown 999:999 "$dir_name"
            sudo chmod 770 "$dir_name"
        fi

        # create YAML for each primary shard
        echo "
    shard${shard}a:
        image: mongo
        command: mongod --keyFile /scripts/mongodb.key --port 27018 --shardsvr --replSet shard${shard} --bind_ip_all --setParameter diagnosticDataCollectionEnabled=false --setParameter maxIndexBuildMemoryUsageMegabytes=10000 --wiredTigerCacheSizeGB 40
        volumes:
            - ${script_dir}:/scripts
            - ${dir_name}:/data/db:delegated
        ulimits:
            nproc: 64000
            nofile: 64000
            memlock: -1
            fsize: -1
            cpu: -1
            as: -1
        logging:
            options:
                max-size: 500m
                max-file: 3
        networks:
            - mongo" | tee -a docker-compose.yml
    done

    # set permissions for remapped docker UIDs/GIDs
    sudo chown 999:999 "${db_dir}"
    #sudo chmod -R 770 "${db_dir}"
    #sudo chmod -R 770 "${mongo_meta_dir}"

    echo "
networks:
    mongo:" | tee -a docker-compose.yml

    # protect docker-compose.yml
    sudo chown root:root docker-compose.yml
    sudo chmod 600 docker-compose.yml

}


build_mongo_init_scripts()
{

    for shard in $(seq $num_shards)
    do
        echo "rs.initiate( 
        { _id: \"shard${shard}\", version: 1, members: [
        { _id: 0, host : \"shard${shard}a:27018\" },
] } )" | sudo tee "${script_dir}/init_shard${shard}.js"
    done

}


build_mongo_config_scripts()
{

    echo "rs.initiate( {
    _id: \"configserver\",
    configsvr: true,
    version: 1,
    members: [
        { _id: 0, host : \"config0:27017\" }
] } )" | sudo tee "${script_dir}/init_configserver.js"

}


build_mongo_db_scripts()
{

    echo '
use config
db.settings.save( { _id:"chunksize", value: 256 } )

use credshed
db.createCollection("accounts")
sh.enableSharding("credshed")
sh.shardCollection("credshed.accounts", {_id: 1})' | sudo tee "${script_dir}/init_db.js"

}


build_mongo_router_scripts()
{

    script_name="${script_dir}/init_router.js"
    echo -n '' | sudo tee "$script_name"

    for shard in $(seq $num_shards)
    do
        echo "sh.addShard(\"shard${shard}/shard${shard}a:27018\")" | sudo tee -a "$script_name"
    done

}



build_mongo_scripts()
{

    sudo mkdir -p "${script_dir}" 2>/dev/null

    # internal authentication key
    openssl rand -base64 741 | sudo tee "${script_dir}/mongodb.key"
    sudo cp mongod.conf "${script_dir}/"

    build_mongo_init_scripts
    build_mongo_config_scripts
    build_mongo_router_scripts

    build_mongo_db_scripts

    sudo chown -R 999:999 "${script_dir}"
    sudo chmod -R 770 "${script_dir}"
    sudo chmod 600 "${script_dir}/mongodb.key"

}



init_shards()
{

    # initialize config server for primary database
    sudo docker-compose exec config0 sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init_configserver.js"
    #sudo docker-compose exec config1 sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init_configserver.js"

    # give config servers some time
    sleep 15

    # initialize shards for primary database
    for i in $(seq $num_shards)
    do
        sudo docker-compose exec "shard${i}a" sh -c "mongo --port 27018 < /scripts/init_shard${i}.js"
    done


    # give shards time to synchronize
    sleep 20

    # initialize router for primary database
    sudo docker-compose exec router sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init_router.js"

    sleep 15

    # shard main collection
    sudo docker-compose exec router sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init_db.js"

}


# populate the database with test entries
init_db()
{

    # test account (credshed.accounts)
    test_account='{"_id" : "moc.elpmaxe|n4bQgYhMB98TxttN", "e" : "test", "u": "test", "p" : "Password1", "h": "2ac9cb7dc02b3c0083eb70898e549b63", "m": "Test account (added automatically)", "s": [NumberInt(1), NumberInt(2)]}'

    # test sources (credshed.sources)
    # normal file
    test_source1='{"_id" : "0000000000000000000000000000000000000000", "source_id": NumberInt(1), "name" : "test_file", "filename": "/tmp/test.txt", "modified_date": ISODate(), "import_finished": true, "created_date": ISODate(), "files": ["/tmp/test.txt"], "description": "test", "top_domains": {"example.com": NumberInt(1)}, "top_password_basewords": {"password": NumberInt(1)}, "top_misc_basewords": {"test": NumberInt(1), "account": NumberInt(1), "added": NumberInt(1), "automatically": NumberInt(1)}, "total_accounts": NumberInt(1), "filesize": NumberInt(26) }'
    # paste
    test_source2='{"_id" : "1111111111111111111111111111111111111111", "source_id": NumberInt(2), "name" : "test_paste", "filename": "/tmp/pastes/2020-02-28_pastebin_text_tEsTiNgG.txt", "modified_date": ISODate(), "import_finished": true, "created_date": ISODate(),  "files": ["/tmp/pastes/2020-02-28_pastebin_text_tEsTiNgG.txt"], "description": "test paste", "top_domains": {"example.com": NumberInt(1)}, "top_password_basewords": {"password": NumberInt(1)}, "top_misc_basewords": {"test": NumberInt(1), "account": NumberInt(1), "added": NumberInt(1), "automatically": NumberInt(1)}, "total_accounts": NumberInt(1), "filesize": NumberInt(26) }'

    echo "
use credshed
db.createCollection('accounts')
db.accounts.insert(${test_account})
db.createCollection('sources')
db.sources.insert(${test_source1})
db.sources.insert(${test_source2})" | sudo tee "${script_dir}/tmp.js"

    exec_tmp_js

}


# delete database content without changing container status
reset_db()
{

    # delete db
    echo '
use credshed
db.accounts.deleteMany({})
db.sources.deleteMany({})' | sudo tee "${script_dir}/tmp.js"

    exec_tmp_js

}


# executes the script in "${script_dir}/tmp.js"
exec_tmp_js()
{

    sudo docker-compose exec "router" sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/tmp.js"

}


if [ $EUID -eq 0 ]
then
    printf "[!] Please run as normal user!\n"
    sleep 10
    printf "[!] Okay, you asked for it.\n"
fi

if [ $# -eq 0 ]
then
    usage
fi


while :
do
    case $1 in
        -p|-P|--prep|prep|1)
            do_db_prep=true
            ;;
        --start|start|2)
            do_start=true
            ;;
        -i|-I|--init|init|3)
            do_start=true
            do_init_db=true
            do_init_shards=true
            ;;
        -c|-C|--clean|clean)
            do_stop=true
            do_clean=true
            ;;
        -d|-D|--delete|--del|delete)
            do_stop=true
            do_delete=true
            ;;
        --stop|stop|-k|-K|--kill|kill)
            do_stop=true
            ;;
        --shards|-n|--num-shards)
            shift
            case $1 in
                ''|*[!0-9]*)
                    printf "[!] Invalid number of shards\n"
                    exit 2
                    ;;
                *) num_shards=$1
                    ;;
            esac
            ;;
        --rebuild|rebuild|-r|-R)
            do_stop=true
            do_delete=true
            do_db_prep=true
            do_start=true
            do_init_shards=true
            do_init_db=true
            ;;
        --reset|reset|-r|-R)
            do_start=true
            do_reset_db=true
            do_init_db=true
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            break
    esac
    shift
done


if [ -n "$do_stop" ]
then
    stop_containers
fi

if [ -n "$do_clean" ]
then
    clean
fi

if [ -n "$do_delete" ]
then
    delete_db
fi

if [ -n "$do_db_prep" ]
then
    build_mongo_scripts
    create_dirs_and_yaml
fi

if [ -n "$do_start" ]
then
    start_daemon
    start_containers
fi

if [ -n "$do_reset_db" ]
then
    reset_db
fi

if [ -n "$do_init_shards" ]
then
    printf 'Sleeping for 60 seconds (a very long time is needed before the config server will respond)\n'
    sleep 60
    init_shards
fi

if [ -n "$do_init_db" ]
then
    init_db
fi