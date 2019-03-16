#!/bin/bash

# by TheTechromancer

. ./.env

usage()
{
	cat <<EOF
Usage: ${0##*/} [option]

  Options:

    start   start dockerd
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
	create_dirs

}


delete_db()
{
	to_delete=( "$mongo_main_dir" "$mongo_meta_dir" )

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


create_dirs()
{

	mongo_dirs=( "$mongo_main_dir" "$mongo_meta_dir" )
	for mongo_dir in "${to_delete[@]}"
	do
		if [ -n "$mongo_dir" -a ! -d "$mongo_dir" ]
		then
			sudo mkdir -p "$mongo_dir"
			sudo chown 231999:231999 "$mongo_dir"
			sudo chmod 770 "$mongo_dir"
		fi
	done
	if [ -n "$srv_dir" -a ! -d "$srv_dir" ]
	then
		sudo mkdir -p "$srv_dir"
	fi

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
	kill_dock
fi

if [ -n "$do_clean" ]
then
	kill_dock
	clean
fi

if [ -n "$do_delete" ]
then
	kill_dock
	delete_db
fi

if [ -n "$do_purge" ]
then
	kill_dock
	clean
fi

if [ -n "$do_start" ]
then
	start_daemon
fi