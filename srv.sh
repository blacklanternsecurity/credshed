#!/bin/bash

. .env

mongo_name="mongo_0"
redis_name="redis_0"
elast_name="elastic_0"
kibana_name="kibana_0"

usage()
{
	cat <<EOF
Usage: ${0##*/} [option]

  Options:

    start   start mongodb container
    kill    kill mongodb container
    shell   interactive shell to container
    clean   remove artifacts such as docker containers & images
    delete  delete entire database

    -m      mountpoint (default $mountpoint)

EOF
exit 0
}


# store index files in tmpfs, sync every 4 hours
# or when container is stopped
build_image()
{
	echo '[+] Building docker image'
	mkdir -p "/tmp/mongo_wrapper"

	cat <<EOF > "/tmp/mongo_wrapper/Dockerfile"
FROM mongo
RUN apt-get -y update || true
RUN apt-get -y install rsync || true
RUN apt-get -y autoclean
RUN apt-get -y autoremove

RUN echo '#!/bin/bash\nfunction sync_index() { rsync -uavr /data/db/index/* /index_persist/; }\n(while true; do sync_index; sleep 14400; done) &\nrsync -uavr /index_persist/* /data/db/index/; mongod --bind_ip_all "\$@"; sync_index; sync' > /tmp/wrapper.sh
RUN chmod 700 /tmp/wrapper.sh

#ENTRYPOINT cat /tmp/wrapper.sh
ENTRYPOINT ["/tmp/wrapper.sh"]
EOF

	docker build "/tmp/mongo_wrapper" -t mongo_wrapper
	rm -r "/tmp/mongo_wrapper"

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


start_mongo()
{

	start_daemon
	#build_image

	if docker ps | grep -q "$mongo_name"
	then
		printf '[i] MongoDB is already started\n'
	else
		printf '[+] Launching MongoDB\n'
		docker rm "$mongo_name" 2>/dev/null
		docker run --name "$mongo_name" --detach --publish 127.0.0.1:27017:27017 \
			--volume "$mongo_dir/configdb:/data/configdb:delegated" \
			--volume "$mongo_dir/db:/data/db:delegated" \
			mongo --wiredTigerDirectoryForIndexes --nojournal \
			--setParameter maxIndexBuildMemoryUsageMegabytes=32000 \
			--setParameter diagnosticDataCollectionEnabled=false \
			--wiredTigerCacheSizeGB 120
			#--setParameter syncdelay=120
			#--tmpfs "/data/db/index" \
			#--volume "$db_dir/db/index:/index_persist" \
			
		sleep 1
		# docker ps >/dev/null 2>&1 || (sudo kill $(pgrep -x dockerd); start_container)
		
		if docker ps | grep -q "$mongo_name"
		then
			printf '[+] MongoDB successfully started\n'
		else
			printf '[!] Failed to start MongoDB\n'
			exit 1
		fi
	fi

}


start_redis()
{

	if docker ps | grep -q "$redis_name"
	then
		printf '[i] Redis is already started\n'
	else
		printf '[+] Launching Redis\n'
		docker rm "$redis_name" 2>/dev/null
		docker run --name "$redis_name" --detach --publish 127.0.0.1:6379:6379 \
			--volume "$redis_dir:/data:delegated" \
			redis redis-server --maxmemory 60000000000 \
			--maxmemory-policy allkeys-random
			#--appendonly yes
		sleep 1
		# docker ps >/dev/null 2>&1 || (sudo kill $(pgrep -x dockerd); start_container)
		
		if docker ps | grep -q "$redis_name"
		then
			printf '[+] Redis successfully started\n'
		else
			printf '[!] Failed to start Redis\n'
			exit 1
		fi
	fi

}


start_containers()
{

	start_daemon
	start_elastic
	start_kibana
	#start_mongo
	#start_redis

}

stop_containers()
{

	printf '[+] Gracefully stopping MongoDB\n'
	#docker exec "mongo_0" bash -c 'kill -2 $(pgrep -x mongod)' 2>/dev/null
	docker exec -it "$mongo_name" bash -c 'mongod --shutdown' 2>/dev/null

	printf '[+] Gracefully stopping Redis\n'
	docker stop -t 9999999 "$redis_name" >/dev/null 2>&1

	printf '[+] Gracefully stopping Elasticsearch\n'
	docker stop -t 9999999 "$elast_name" >/dev/null 2>&1
	
	while :
	do
		(docker ps | grep -q "$elast_name\|$mongo_name\|$redis_name") || break
		sleep 1
	done

}


kill_containers()
{

	printf '[+] Killing containers\n'
	docker stop "$mongo_name" --time 30 2>/dev/null
	docker stop "$redis_name" --time 30 2>/dev/null

}


kill_dock()
{

	if pgrep dockerd >/dev/null
	then
		stop_containers

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


shell_dock()
{

	docker exec -it "$mongo_name" bash

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
	create_dirs

}


delete_db()
{

	kill_dock
	#printf '\n[!] DELETES ENTIRE DB - PRESS CTRL+C TO CANCEL\n\n'
	#sleep 2
	sudo rm -r "$mongo_dir"
	sudo rm -r "$redis_dir"
	sudo rm -r "$elast_dir"
	create_dirs
	printf '[+] Done.\n'

}


create_dirs()
{

	# if [ ! -d "$index_dir" ]
	# then
	# 	sudo mkdir -p "$index_dir"
	# 	sudo chown 231999:231999 "$index_dir"
	# 	sudo chmod 770 "$index_dir"
	# fi
	if [ ! -d "$mongo_dir" ]
	then
		sudo mkdir -p "$mongo_dir"
		sudo chown 231999:231999 "$mongo_dir"
		sudo chmod 770 "$mongo_dir"
	fi
	if [ ! -d "$srv_dir" ]
	then
		sudo mkdir -p "$srv_dir"
	fi
	if [ ! -d "$redis_dir" ]
	then
		sudo mkdir -p "$redis_dir"
		sudo chown 231999:231999 "$redis_dir"
		sudo chmod 770 "$redis_dir"
	fi
	if [ ! -d "$elast_dir" ]
	then
		sudo mkdir -p "$elast_dir"
		sudo chown 232000:232000 "$elast_dir"
		sudo chmod 770 "$elast_dir"
	fi
	#sudo rm -r "$db_dir/index"
	#sudo ln -s "$index_dir" "$db_dir/index"

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
		-c|-C|--clean|clean)
			clean
			;;
		-d|-D|--delete|--del|delete)
			delete_db
			;;
		--start|start)
			do_start=true
			;;
		--stop|stop)
			do_stop=true
			;;
		-k|-K|--kill|kill)
			do_kill=true
			;;
		-ms|--mongo-shell|mongo-shell|--mongodb-shell|mongodb-shell)
			mongo_shell=true
			;;
		-rs|--redis-shell|redis-shell)
			redis_shell=true
			;;
		-m|-M|--mount|--mountpoint)
			shift
			mountpoint="$1"
			break
			;;
		-h|--help|help)
			usage
			;;
		*)
			break
	esac
	shift
done

# make sure directories exist
create_dirs

if [ -n "$do_stop" ]
then
	stop_containers
fi
if [ -n "$mongo_shell" ]
then
	start_containers
	docker exec -it "$mongo_name" bash
elif [ -n "$redis_shell" ]
then
	start_containers
	docker exec -it "$redis_name" bash
elif [ -n "$do_kill" ]
then
	kill_dock
elif [ -n "$do_start" ]
then
	start_daemon
	#start_containers
fi
