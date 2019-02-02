sh.addShard("shard0/shard0a:27018")
sh.addShard("shard1/shard1a:27018")

use dump
db.createCollection('accounts')
sh.enableSharding('dump')
sh.shardCollection('dump.accounts', {_id: 1})