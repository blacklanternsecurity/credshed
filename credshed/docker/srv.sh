#!/bin/bash

# by TheTechromancer

. ./srv.config

usage()
{
    cat <<EOF
Usage: ${0##*/} [option]

  Options:

    [1] prep    create init scripts & directories
    [2] start   start containers
    [3] init    initialize mongodb shards
        stop    stop dockerd
        clean   remove artifacts such as docker containers & images
        delete  delete entire database

EOF
exit 0
}



start_daemon()
{

    if ! grep -q "dockremap:231000:65536" /etc/subuid
    then
        echo "dockremap:231000:65536" | sudo tee /etc/subuid >/dev/null 2>&1
    fi
    if ! grep -q "dockremap:231000:65536" /etc/subgid
    then
        echo "dockremap:231000:65536" | sudo tee /etc/subgid >/dev/null 2>&1
    fi

    # cache sudo privileges to prevent script from dying
    sudo echo -n ''

    if ! pgrep dockerd >/dev/null
    then
        printf '[+] Starting daemon\n'
        (sudo dockerd --log-level fatal --userns-remap "default" --data-root "$srv_dir") &

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



kill_dock()
{

    if pgrep -x dockerd >/dev/null
    then
        #stop_containers

        printf '[+] Killing daemon\n'
        sudo kill $(pgrep -x dockerd) 2>/dev/null
        while :
        do
            pgrep -x dockerd >/dev/null || break
            sleep .1
        done
        printf "[+] It's dead\n"

    else
        printf '[i] dockerd daemon not running\n'
    fi

}


clean()
{

    start_daemon
    sudo docker kill $(docker ps -q) >/dev/null 2>&1
    sudo docker rm $(docker ps -a -q) >/dev/null 2>&1
    sudo docker rmi $(docker images -q) >/dev/null 2>&1
    docker kill $(docker ps -q) >/dev/null 2>&1
    docker rm $(docker ps -a -q) >/dev/null 2>&1
    docker rmi $(docker images -q) >/dev/null 2>&1
    sudo rm /etc/subgid /etc/subuid >/dev/null 2>&1
    kill_dock
    while :
    do
        pgrep dockerd >/dev/null || break
        sleep .1
    done

    sudo rm -r "$srv_dir"
    create_dirs_and_yaml

}


delete_db()
{
    to_delete=( "$mongo_main_dir" "$mongo_meta_dir" "$mongo_script_dir" )

    kill_dock
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

    create_dirs
    printf '[+] Done.\n'

}


create_dirs_and_yaml()
{

    >docker-compose.yml

    echo "version: '3'

services:" >> docker-compose.yml

    # create YAML for primary router
    echo "
    main_router:
        image: mongo
        command: mongos --port 27017 --configdb main_configserver/main_config0:27017 --bind_ip_all
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
            - main_config0" >> docker-compose.yml
    for shard in $(seq 1 $num_shards)
    do
        echo "            - main_shard${shard}a" >> docker-compose.yml
    done
    echo "        networks:
            - mongo_main" >> docker-compose.yml

    # create YAML for primary config server
    echo "
    main_config0:
        image: mongo
        command: mongod --port 27017 --configsvr --replSet main_configserver --bind_ip_all
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${mongo_main_dir}/mongo_config_0:/data/configdb:delegated
        networks:
            - mongo_main" >> docker-compose.yml

    # create YAML for metadata router
    echo "
    meta_router:
        image: mongo
        command: mongos --port 27017 --configdb meta_configserver/meta_config0:27017 --bind_ip_all
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
            - meta_config0" >> docker-compose.yml
    for shard in $(seq 1 $num_shards)
    do
        echo "            - meta_shard${shard}a" >> docker-compose.yml
    done
    echo "        networks:
            - mongo_meta" >> docker-compose.yml

    # create YAML for metadata config server
    echo "
    meta_config0:
        image: mongo
        command: mongod --port 27017 --configsvr --replSet meta_configserver --bind_ip_all
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${mongo_meta_dir}/mongo_config_0:/data/configdb:delegated
        networks:
            - mongo_meta" >> docker-compose.yml


    # create parent directory for primary config server
    sudo mkdir -p "${mongo_main_dir}/mongo_config_0" 2>/dev/null
    sudo chown 231999:231999 "${mongo_main_dir}/mongo_config_0"
    sudo chmod 777 "${mongo_main_dir}/mongo_config_0"

    # create parent directory for metatdata config server
    sudo mkdir -p "${mongo_meta_dir}/mongo_config_0" 2>/dev/null
    sudo chown 231999:231999 "${mongo_meta_dir}/mongo_config_0"
    sudo chmod 777 "${mongo_main_dir}/mongo_config_0"

    # create directories & containers for primary database shards
    for shard in $(seq 1 $num_shards)
    do
        dir_name="${mongo_main_dir}/mongo_shard_${shard}a"
        if [ -n "$dir_name" -a ! -d "$dir_name" ]
        then
            sudo mkdir -p "$dir_name" 2>/dev/null
            sudo chown 231999:231999 "$dir_name"
            sudo chmod 770 "$dir_name"
        fi

        # create YAML for each primary shard
        echo "
    main_shard${shard}a:
        image: mongo
        command: mongod --port 27018 --shardsvr --replSet main_shard${shard} --bind_ip_all --setParameter maxIndexBuildMemoryUsageMegabytes=2000 --setParameter diagnosticDataCollectionEnabled=false --wiredTigerCacheSizeGB 5
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${dir_name}:/data/db:delegated
        ulimits:
            nproc: 65535
            nofile:
                soft: 100000
                hard: 200000
        networks:
            - mongo_main" >> docker-compose.yml
    done


    # create directories & containers for metdata database shards
    for shard in $(seq 1 $num_shards)
    do
        dir_name="${mongo_meta_dir}/mongo_shard_${shard}a"
        if [ -n "$dir_name" -a ! -d "$dir_name" ]
        then
            sudo mkdir -p "$dir_name" 2>/dev/null
            sudo chown 231999:231999 "$dir_name"
            sudo chmod 770 "$dir_name"
        fi

        # create YAML for each metadata shard
        echo "
    meta_shard${shard}a:
        image: mongo
        command: mongod --port 27018 --shardsvr --replSet meta_shard${shard} --bind_ip_all --setParameter maxIndexBuildMemoryUsageMegabytes=2000 --setParameter diagnosticDataCollectionEnabled=false --wiredTigerCacheSizeGB 5
        volumes:
            - ${mongo_script_dir}:/scripts
            - ${dir_name}:/data/db:delegated
        ulimits:
            nproc: 65535
            nofile:
                soft: 100000
                hard: 200000
        networks:
            - mongo_meta" >> docker-compose.yml
    done

    # set permissions for remapped docker UIDs/GIDs
    #sudo chown -R 231999:231999 "${mongo_main_dir}"
    #sudo chown -R 231999:231999 "${mongo_meta_dir}"
    #sudo chmod -R 770 "${mongo_main_dir}"
    #sudo chmod -R 770 "${mongo_meta_dir}"

    echo "
networks:
    mongo_main:
    mongo_meta:" >> docker-compose.yml


    if [ -n "$srv_dir" -a ! -d "$srv_dir" ]
    then
        sudo mkdir -p "$srv_dir"
    fi

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
db.createCollection("account_tags")
sh.enableSharding("credshed")
sh.shardCollection("credshed.account_tags", {_id: 1})' | sudo tee "${mongo_script_dir}/init-meta_db.js"

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

    build_mongo_init_scripts 'main'
    build_mongo_init_scripts 'meta'

    build_mongo_config_scripts 'main'
    build_mongo_config_scripts 'meta'

    build_mongo_router_scripts 'main'
    build_mongo_router_scripts 'meta'

    build_mongo_db_scripts

    sudo chown -R 231999:231999 "${mongo_script_dir}"
    sudo chmod -R 770 "${mongo_script_dir}"

}



init_database()
{

    # intialize config server for primary database
    docker-compose exec main_config0 sh -c "mongo --port 27017 < /scripts/init-main_configserver.js"
    # intialize config server for metadata database
    docker-compose exec meta_config0 sh -c "mongo --port 27017 < /scripts/init-meta_configserver.js"

    # give config servers some time
    sleep 10

    # initialize shards for primary database
    for i in $(seq $num_shards)
    do
        docker-compose exec "main_shard${i}a" sh -c "mongo --port 27018 < /scripts/init-main_shard${i}.js"
    done

    # initialize shards for metadata database
    for i in $(seq $num_shards)
    do
        docker-compose exec "meta_shard${i}a" sh -c "mongo --port 27018 < /scripts/init-meta_shard${i}.js"
    done

    # give shards time to synchronize
    sleep 20

    # initialize router for primary database
    docker-compose exec main_router sh -c "mongo --port 27017 < /scripts/init-main_router.js"
    # initialize router for metadata database
    docker-compose exec meta_router sh -c "mongo --port 27017 < /scripts/init-meta_router.js"

    sleep 15

    # create primary database & collections
    docker-compose exec main_router sh -c "mongo --port 27017 < /scripts/init-main_db.js"
    # create metadata database & collection
    docker-compose exec meta_router sh -c "mongo --port 27017 < /scripts/init-meta_db.js"

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
        -p|-P|--prep|prep)
            do_db_prep=true
            ;;
        -i|-I|--init|init)
            do_init_db=true
            ;;
        -c|-C|--clean|clean)
            do_clean=true
            ;;
        -d|-D|--delete|--del|delete)
            do_delete=true
            ;;
        --start|start)
            do_start=true
            ;;
        --stop|stop|-k|-K|--kill|kill)
            do_stop=true
            ;;
        --purge|purge)
            do_purge=true
            ;;
        --shards)
            shift
            case $1 in
                ''|*[!0-9]*) echo "Invalid number of shards" ;;
                *) num_shards=$1 ;;
            esac
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
    docker-compose down
    # kill_dock
fi

if [ -n "$do_clean" ]
then
    kill_dock
    clean
fi

if [ -n "$do_delete" ]
then
    # kill_dock
    docker-compose down
    delete_db
fi

if [ -n "$do_purge" ]
then
    kill_dock
    clean
fi

if [ -n "$do_db_prep" ]
then
    build_mongo_scripts
    create_dirs_and_yaml
fi

if [ -n "$do_start" ]
then
    start_daemon
    docker-compose up -d
fi

if [ -n "$do_init_db" ]
then
    init_database
fi