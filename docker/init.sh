#!/bin/bash
docker-compose exec config0 sh -c "mongo --port 27017 < /scripts/init-configserver.js"
sleep 5
docker-compose exec shard0a sh -c "mongo --port 27018 < /scripts/init-shard0.js"
docker-compose exec shard1a sh -c "mongo --port 27018 < /scripts/init-shard1.js"

sleep 15
docker-compose exec router sh -c "mongo --port 27017 < /scripts/init-router.js"
sleep 10
docker-compose exec router sh -c "mongo --port 27017 < /scripts/init-db.js"