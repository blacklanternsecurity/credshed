# test account (credshed.accounts)
test_account='{"_id" : "moc.elpmaxe|n4bQgYhMB98TxttN", "e" : "test", "u": "test", "p" : "Password1", "h": "2ac9cb7dc02b3c0083eb70898e549b63", "m": "Test account (added automatically)"}'

# test sources (credshed.sources)
# normal file
test_source1='{"_id" : NumberInt(1), "name" : "test_file", "filename": "/tmp/test.txt", "modified_date": ISODate(), "import_finished": true, "created_date": ISODate(), "hash": "0000000000000000000000000000000000000000", "files": ["/tmp/test.txt"], "description": "test", "top_domains": {"example.com": NumberInt(1)}, "top_password_basewords": {"password": NumberInt(1)}, "top_misc_basewords": {"test": NumberInt(1), "account": NumberInt(1), "added": NumberInt(1), "automatically": NumberInt(1)}, "total_accounts": NumberInt(1), "unique_accounts": NumberInt(1), "filesize": NumberInt(26) }'
# paste
test_source2='{"_id" : NumberInt(2), "name" : "test_paste", "filename": "/tmp/pastes/2020-02-28_pastebin_text_tEsTiNgG.txt", "modified_date": ISODate(), "import_finished": true, "created_date": ISODate(), "hash": "0000000000000000000000000000000000000000", "files": ["/tmp/pastes/2020-02-28_pastebin_text_tEsTiNgG.txt"], "description": "test paste", "top_domains": {"example.com": NumberInt(1)}, "top_password_basewords": {"password": NumberInt(1)}, "top_misc_basewords": {"test": NumberInt(1), "account": NumberInt(1), "added": NumberInt(1), "automatically": NumberInt(1)}, "total_accounts": NumberInt(1), "unique_accounts": NumberInt(1), "filesize": NumberInt(26) }'

# test account metadata (credshed.account_metadata)
test_account_metadata='{"_id" : "moc.elpmaxe|n4bQgYhMB98TxttN", "s": [NumberInt(1), NumberInt(2)] }'