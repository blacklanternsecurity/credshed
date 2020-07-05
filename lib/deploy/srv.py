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
{master_node}
{data_nodes}
{kibana_node}

networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.57.0/24
'''

master_node_template = '''
  {node_name}:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.7.0
    ports:
      - "127.0.0.1:9200:9200"
      - "127.0.0.1:9300:9300"
    volumes:
      - type: bind
        source: {data_dir}/{node_name}
        target: /usr/share/elasticsearch/data
        consistency: delegated
    environment:
      # max memory usage
      - ES_JAVA_OPTS=-Xmx{mem}g -Xms{mem}g
      # disable memory swapping
      - bootstrap.memory_lock=true
      # single node
      #- discovery.type=single-node
      # node name
      - node.name={node_name}
      # node processors
      - node.processors={cpus}
      # master-eligible node
      - node.master=true
      - node.data=false
      # initial master node
      - cluster.initial_master_nodes={node_name}
      # master-eligible nodes
      - discovery.seed_hosts={node_name}
      # authentication
      - ELASTICSEARCH_USERNAME={username}
      - ELASTICSEARCH_PASSWORD={password}
    # allows for swap disablement
    ulimits:
      memlock:
        soft: -1
        hard: -1
'''

data_node_template = '''
  {node_name}:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.7.0
    volumes:
      - type: bind
        source: {data_dir}/{node_name}
        target: /usr/share/elasticsearch/data
        consistency: delegated
    expose:
      - 9200
      - 9300
    environment:
      # max memory usage
      - ES_JAVA_OPTS=-Xmx{mem}g -Xms{mem}g
      # extra memory for indexing
      - indices.memory.index_buffer_size={index_mem:.0f}m
      # disable memory swapping
      - bootstrap.memory_lock=true
      # single node
      #- discovery.type=single-node
      # node name
      - node.name={node_name}
      # node processors
      - node.processors={cpus}
      # master-eligible node
      - node.master=false
      # initial master node
      - cluster.initial_master_nodes={master_node_name}
      # master-eligible nodes
      - discovery.seed_hosts={master_node_name}
      # authentication
      - ELASTICSEARCH_USERNAME={username}
      - ELASTICSEARCH_PASSWORD={password}
    # allows for swap disablement
    ulimits:
      memlock:
        soft: -1
        hard: -1
'''

kibana_node_template = '''
  kibana:
    image: docker.elastic.co/kibana/kibana:7.7.0
    ports:
      - "127.0.0.1:5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://{master_node_name}:9200
      - ELASTICSEARCH_USERNAME={username}
      - ELASTICSEARCH_PASSWORD={password}
      - XPACK_MONITORING_ENABLED=true
    depends_on:
      - es_master
      - {data_node_list}
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