#!/usr/bin/env python3

import sys
import argparse
from os import sysconf
from pathlib import Path
from multiprocessing import cpu_count

credshed_path = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(credshed_path))
from lib.config import config


docker_compose_template = '''
version: '3.7'

services:
{mongo_router_node}
{mongo_config_node}
{mongo_data_nodes}

networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.57.0/24
'''

mongo_router_template = '''
  {node_name}:
    image: mongo
    command: mongos --keyFile /scripts/mongodb.key --port 27017 --configdb main_configserver/main_config0:27017 --bind_ip_all
    ports:
      - \"127.0.0.1:27000:27017\"
    volumes:
      - {mongo_script_dir}:/scripts
    ulimits:
      nproc: 65535
      nofile:
        soft: 100000
        hard: 200000
    depends_on:
      - main_config0
      - {mongo_shards}
    networks:
        - mongo_main
'''

mongo_config_template = '''
  {node_name}:
    image: mongo
    command: mongod --keyFile /scripts/mongodb.key --port 27017 --configsvr --replSet main_configserver --bind_ip_all
    volumes:
      - {mongo_script_dir}:/scripts
      - {data_dir}/{node_name}:/data/configdb:delegated
    environment:
      - MONGO_INITDB_ROOT_USERNAME=${mongo_user}
      - MONGO_INITDB_ROOT_PASSWORD=${mongo_pass}
    networks:
      - mongo_main
'''

mongo_data_template = '''
  {node_name}:
      image: mongo
      command: mongod --keyFile /scripts/mongodb.key --port 27018 --shardsvr --replSet main_shard{shard} --bind_ip_all --setParameter maxIndexBuildMemoryUsageMegabytes=2000 --setParameter diagnosticDataCollectionEnabled=false --wiredTigerCacheSizeGB 5
      volumes:
        - ${mongo_script_dir}:/scripts
        - ${dir_name}:/data/db:delegated
      ulimits:
        nproc: 65535
        nofile:
          soft: 100000
          hard: 200000
      networks:
        - mongo_main
'''


if __name__ == '__main__':

    # number of elastic nodes
    num_nodes = int(config['CREDSHED']['nodes'])
    # number of CPU cores
    cpus = cpu_count()
    # amount of memory
    mem_bytes = sysconf('SC_PAGE_SIZE') * sysconf('SC_PHYS_PAGES')
    mem_gib = mem_bytes / (1024.**3)
    elastic_mem = mem_gib / 2

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nodes', type=int, default=num_nodes, help='number of elastic nodes (not counting master)')
    parser.add_argument('-c', '--cpus',  type=int, default=cpus, help='number of CPU cores')
    parser.add_argument('-d', '--mkdir', action='store_true', help='create directories for data nodes')

    options = parser.parse_args()

    mem_per_node = max(4, min(25, int(elastic_mem / options.nodes)+1))
    #cpus_per_node = max(4, int(options.cpus / options.nodes * 2)+1)
    cpus_per_node = int(options.cpus / 2)
    index_mem_per_node = max(1024, min((mem_per_node*1024)*.66, int(512 * (int(config['CREDSHED']['shards']) / options.nodes))))

    base_node_name = 'es_'
    master_node_name = f'{base_node_name}master'

    if options.mkdir:
        master_data_dir = Path(config['CREDSHED']['data_dir']) / master_node_name
        print(f'Creating {master_data_dir}')
        master_data_dir.mkdir(parents=True, exist_ok=True)
        for i in range(1, options.nodes+1):
            data_node_name = f'{base_node_name}{i}'
            node_data_dir = Path(config['CREDSHED']['data_dir']) / data_node_name
            print(f'Creating {node_data_dir}')
            node_data_dir.mkdir(parents=True, exist_ok=True)

    else:
        master_node = master_node_template.format(
            node_name=master_node_name,
            cpus=cpus_per_node,
            mem=mem_per_node,
            data_dir=config['CREDSHED']['data_dir'],
            username=config['CREDSHED']['username'],
            password=config['CREDSHED']['password']
        )

        data_nodes = []
        data_node_list = []
        for i in range(1, options.nodes+1):
            data_node_name = f'{base_node_name}{i}'

            data_node_list.append(f'{data_node_name}')
            data_nodes.append(data_node_template.format(
                node_name=data_node_name,
                master_node_name=master_node_name,
                cpus=cpus_per_node,
                mem=mem_per_node,
                index_mem=index_mem_per_node,
                data_dir=config['CREDSHED']['data_dir'],
                username=config['CREDSHED']['username'],
                password=config['CREDSHED']['password']
            ))

        kibana_node = kibana_node_template.format(
            master_node_name=master_node_name,
            data_node_list='\n      - '.join(data_node_list),
            username=config['CREDSHED']['username'],
            password=config['CREDSHED']['password']
        )

        docker_compose_file = docker_compose_template.format(
            master_node=master_node,
            data_nodes='\n'.join(data_nodes),
            kibana_node=kibana_node
        )

        print(docker_compose_file)