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
    to_delete=( "$mongo_main_dir" "$mongo_meta_dir" "$mongo_script_dir" )

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
    main_router:
        image: mongo
        command: mongos --keyFile /scripts/mongodb.key --port 27017 --configdb main_configserver/main_config0:27017 --bind_ip_all
        ports:
            - \"127.0.0.1:27000:27017\"
        volumes:
            - ${mongo_script_dir}:/scripts
        ulimits:
            nproc: 65535
            nofile:
                soft: 100000
                hard: 200000
        depends_on:
            - main_config0" | tee -a docker-compose.yml
    for shard in $(seq 1 $num_shards)
    do
        echo "            - main_shard${shard}a" | tee -a docker-compose.yml
    done
    echo "        networks:
            - mongo_main" | tee -a docker-compose.yml

    # create YAML for primary config server
    echo "
    main_config0:
        image: mongo
        command: mongod --keyFile /scripts/mongodb.key --port 27017 --configsvr --replSet main_configserver --bind_ip_all
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${mongo_main_dir}/mongo_config_0:/data/configdb:delegated
        environment:
            - MONGO_INITDB_ROOT_USERNAME=${mongo_user}
            - MONGO_INITDB_ROOT_PASSWORD=${mongo_pass}
        networks:
            - mongo_main" | tee -a docker-compose.yml

    # create YAML for metadata router
    echo "
    meta_router:
        image: mongo
        command: mongos --keyFile /scripts/mongodb.key --port 27017 --configdb meta_configserver/meta_config0:27017 --bind_ip_all
        ports:
            - \"127.0.0.1:27001:27017\"
        volumes:
            - ${mongo_script_dir}:/scripts
        ulimits:
            nproc: 65535
            nofile:
                soft: 100000
                hard: 200000
        depends_on:
            - meta_config0" | tee -a docker-compose.yml
    for shard in $(seq 1 $num_shards)
    do
        echo "            - meta_shard${shard}a" | tee -a docker-compose.yml
    done
    echo "        networks:
            - mongo_meta" | tee -a docker-compose.yml

    # create YAML for metadata config server
    echo "
    meta_config0:
        image: mongo
        command: mongod --keyFile /scripts/mongodb.key --port 27017 --configsvr --replSet meta_configserver --bind_ip_all
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${mongo_meta_dir}/mongo_config_0:/data/configdb:delegated
        environment:
            - MONGO_INITDB_ROOT_USERNAME=${mongo_user}
            - MONGO_INITDB_ROOT_PASSWORD=${mongo_pass}
        networks:
            - mongo_meta"| tee -a docker-compose.yml


    # create parent directory for primary config server
    sudo mkdir -p "${mongo_main_dir}/mongo_config_0" 2>/dev/null
    sudo chown 999:999 "${mongo_main_dir}/mongo_config_0"
    #sudo chmod 777 "${mongo_main_dir}/mongo_config_0"

    # create parent directory for metatdata config server
    sudo mkdir -p "${mongo_meta_dir}/mongo_config_0" 2>/dev/null
    sudo chown 999:999 "${mongo_meta_dir}/mongo_config_0"
    #sudo chmod 777 "${mongo_main_dir}/mongo_config_0"

    # create directories & containers for primary database shards
    for shard in $(seq 1 $num_shards)
    do
        dir_name="${mongo_main_dir}/mongo_shard_${shard}a"
        if [ -n "$dir_name" -a ! -d "$dir_name" ]
        then
            sudo mkdir -p "$dir_name" 2>/dev/null
            sudo chown 999:999 "$dir_name"
            sudo chmod 770 "$dir_name"
        fi

        # create YAML for each primary shard
        echo "
    main_shard${shard}a:
        image: mongo
        command: mongod --keyFile /scripts/mongodb.key --port 27018 --shardsvr --replSet main_shard${shard} --bind_ip_all --setParameter maxIndexBuildMemoryUsageMegabytes=2000 --setParameter diagnosticDataCollectionEnabled=false --wiredTigerCacheSizeGB 5
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${dir_name}:/data/db:delegated
        ulimits:
            nproc: 65535
            nofile:
                soft: 100000
                hard: 200000
        networks:
            - mongo_main" | tee -a docker-compose.yml
    done


    # create directories & containers for metdata database shards
    for shard in $(seq 1 $num_shards)
    do
        dir_name="${mongo_meta_dir}/mongo_shard_${shard}a"
        if [ -n "$dir_name" -a ! -d "$dir_name" ]
        then
            sudo mkdir -p "$dir_name" 2>/dev/null
            sudo chown 999:999 "$dir_name"
            sudo chmod 770 "$dir_name"
        fi

        # create YAML for each metadata shard
        echo "
    meta_shard${shard}a:
        image: mongo
        command: mongod --keyFile /scripts/mongodb.key --port 27018 --shardsvr --replSet meta_shard${shard} --bind_ip_all --setParameter maxIndexBuildMemoryUsageMegabytes=2000 --setParameter diagnosticDataCollectionEnabled=false --wiredTigerCacheSizeGB 5
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${dir_name}:/data/db:delegated
        ulimits:
            nproc: 65535
            nofile:
                soft: 100000
                hard: 200000
        networks:
            - mongo_meta" | tee -a docker-compose.yml
    done

    # set permissions for remapped docker UIDs/GIDs
    sudo chown -R 999:999 "${mongo_main_dir}"
    sudo chown -R 999:999 "${mongo_meta_dir}"
    #sudo chmod -R 770 "${mongo_main_dir}"
    #sudo chmod -R 770 "${mongo_meta_dir}"

    echo "
networks:
    mongo_main:
    mongo_meta:" | tee -a docker-compose.yml

    # protect docker-compose.yml
    sudo chown root:root docker-compose.yml
    sudo chmod 600 docker-compose.yml

}


build_mongo_init_scripts()
{

    # $1 = prefix - e.g. "main", "meta"

    for shard in $(seq $num_shards)
    do
        echo "rs.initiate( 
        { _id: \"${1}_shard${shard}\", version: 1, members: [
        { _id: 0, host : \"${1}_shard${shard}a:27018\" },
] } )" | sudo tee "${mongo_script_dir}/init-${1}_shard${shard}.js"
    done

}


build_mongo_config_scripts()
{

    # $1 = prefix - e.g. "main", "meta"

    echo "rs.initiate( {
    _id: \"${1}_configserver\",
    configsvr: true,
    version: 1,
    members: [
        { _id: 0, host : \"${1}_config0:27017\" }
] } )" | sudo tee "${mongo_script_dir}/init-${1}_configserver.js"

}


build_mongo_db_scripts()
{

    echo '
use credshed
db.createCollection("accounts")
sh.enableSharding("credshed")
sh.shardCollection("credshed.accounts", {_id: 1})' | sudo tee "${mongo_script_dir}/init-main_db.js"


    echo '
use credshed
db.createCollection("accounts_metadata")
sh.enableSharding("credshed")
sh.shardCollection("credshed.accounts_metadata", {_id: 1})' | sudo tee "${mongo_script_dir}/init-meta_db.js"

}


build_mongo_router_scripts()
{

    # $1 = prefix - e.g. "main", "meta"

    script_name="${mongo_script_dir}/init-${1}_router.js"
    echo -n '' | sudo tee "$script_name"

    for shard in $(seq $num_shards)
    do
        echo "sh.addShard(\"${1}_shard${shard}/${1}_shard${shard}a:27018\")" | sudo tee -a "$script_name"
    done

}



build_mongo_scripts()
{

    sudo mkdir -p "${mongo_script_dir}" 2>/dev/null

    # internal authentication key
    openssl rand -base64 741 | sudo tee "${mongo_script_dir}/mongodb.key"

    build_mongo_init_scripts 'main'
    build_mongo_init_scripts 'meta'

    build_mongo_config_scripts 'main'
    build_mongo_config_scripts 'meta'

    build_mongo_router_scripts 'main'
    build_mongo_router_scripts 'meta'

    build_mongo_db_scripts

    sudo chown -R 999:999 "${mongo_script_dir}"
    sudo chmod -R 770 "${mongo_script_dir}"
    sudo chmod 600 "${mongo_script_dir}/mongodb.key"

}



init_shards()
{

    # intialize config server for primary database
    sudo docker-compose exec main_config0 sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init-main_configserver.js"
    # intialize config server for metadata database
    sudo docker-compose exec meta_config0 sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init-meta_configserver.js"

    # give config servers some time
    sleep 15

    # initialize shards for primary database
    for i in $(seq $num_shards)
    do
        sudo docker-compose exec "main_shard${i}a" sh -c "mongo --port 27018 < /scripts/init-main_shard${i}.js"
    done

    # initialize shards for metadata database
    for i in $(seq $num_shards)
    do
        sudo docker-compose exec "meta_shard${i}a" sh -c "mongo --port 27018 < /scripts/init-meta_shard${i}.js"
    done

    # give shards time to synchronize
    sleep 20

    # initialize router for primary database
    sudo docker-compose exec main_router sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init-main_router.js"
    # initialize router for metadata database
    sudo docker-compose exec meta_router sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init-meta_router.js"

    sleep 15

    # shard main collection
    sudo docker-compose exec main_router sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init-main_db.js"
    # shard meta collection
    sudo docker-compose exec meta_router sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/init-meta_db.js"


}


# populate the database with test entries
init_db()
{

    . ./test_data.sh

    echo "
use credshed
db.createCollection('accounts')
db.accounts.insert(${test_account})
db.createCollection('sources')
db.sources.insert(${test_source1})
db.sources.insert(${test_source2})" | sudo tee "${mongo_script_dir}/tmp.js"

    exec_tmp_js main


    echo "
use credshed
db.createCollection('accounts_metadata')
db.accounts_metadata.insert(${test_account_metadata})" | sudo tee "${mongo_script_dir}/tmp.js"

    exec_tmp_js meta

}


# delete database content without changing container status
reset_db()
{

    # delete main db
    echo '
use credshed
db.accounts.deleteMany({})
db.sources.deleteMany({})' | sudo tee "${mongo_script_dir}/tmp.js"

    exec_tmp_js main
    

    # delete meta db
    echo '
use credshed
db.accounts_metadata.deleteMany({})' | sudo tee "${mongo_script_dir}/tmp.js"

    exec_tmp_js meta

}


# executes the script in "${mongo_script_dir}/tmp.js" in either main or meta router
exec_tmp_js()
{

    sudo docker-compose exec "${1}_router" sh -c "mongo -u ${mongo_user} -p ${mongo_pass} --port 27017 < /scripts/tmp.js"

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
    sleep 10
fi

if [ -n "$do_reset_db" ]
then
    reset_db
fi

if [ -n "$do_init_shards" ]
then
    init_shards
fi

if [ -n "$do_init_db" ]
then
    init_db
fi