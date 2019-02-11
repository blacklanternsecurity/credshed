use credshed
db.createCollection('accounts')
sh.enableSharding('credshed')
sh.shardCollection('credshed.accounts', {_id: 1})
db.accounts.insert({'_id': 'b8BeiawkbVr21Llu', 'email': 'qc', 'domain': 'ude.nosmelc', 'password': 'cherry148888'})