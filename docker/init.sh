#!/bin/bash

docker-compose exec main_config0 sh -c "mongo --port 27017 < /scripts/init-main_configserver.js"

docker-compose exec meta_config0 sh -c "mongo --port 27017 < /scripts/init-meta_configserver.js"


sleep 10

docker-compose exec main_shard0a sh -c "mongo --port 27018 < /scripts/init-main_shard0.js"
docker-compose exec main_shard1a sh -c "mongo --port 27018 < /scripts/init-main_shard1.js"
docker-compose exec main_shard2a sh -c "mongo --port 27018 < /scripts/init-main_shard2.js"
docker-compose exec main_shard3a sh -c "mongo --port 27018 < /scripts/init-main_shard3.js"

docker-compose exec meta_shard0a sh -c "mongo --port 27018 < /scripts/init-meta_shard0.js"
docker-compose exec meta_shard1a sh -c "mongo --port 27018 < /scripts/init-meta_shard1.js"
docker-compose exec meta_shard2a sh -c "mongo --port 27018 < /scripts/init-meta_shard2.js"
docker-compose exec meta_shard3a sh -c "mongo --port 27018 < /scripts/init-meta_shard3.js"


sleep 20

docker-compose exec main_router sh -c "mongo --port 27017 < /scripts/init-main_router.js"

docker-compose exec meta_router sh -c "mongo --port 27017 < /scripts/init-meta_router.js"


sleep 15

docker-compose exec main_router sh -c "mongo --port 27017 < /scripts/init-main_db.js"

docker-compose exec meta_router sh -c "mongo --port 27017 < /scripts/init-meta_db.js"