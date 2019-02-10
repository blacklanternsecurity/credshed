sh.addShard("shard0/shard0a:27018")
sh.addShard("shard1/shard1a:27018")

use dump
db.createCollection('accounts')
sh.enableSharding('dump')
db.accounts.insert({'_id': 'b8BeiawkbVr21Llu', 'email': 'qc', 'domain': 'ude.nosmelc', 'password': 'cherry148888'})
sh.shardCollection('dump.accounts', {_id: 1})