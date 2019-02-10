use dump
db.createCollection('accounts')
sh.enableSharding('dump')
sh.shardCollection('dump.accounts', {_id: 1})
db.accounts.insert({'_id': 'b8BeiawkbVr21Llu', 'email': 'qc', 'domain': 'ude.nosmelc', 'password': 'cherry148888'})