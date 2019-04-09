use credshed
db.createCollection('accounts')
sh.enableSharding('credshed')
sh.shardCollection('credshed.accounts', {_id: 1})