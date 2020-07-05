test_dir=/tmp/credshed_test
mkdir -p $test_dir/deeper
echo 'multiple_hashes@evilcorp.com:multiple_hashes:5f4dcc3b5aa765d61d8327deb882cf99,dc647eb65e6711e155375218212b3964' > $test_dir/multiple_hashes
echo 'standard@evilcorp.com:5f4dcc3b5aa765d61d8327deb882cf99' > $test_dir/standard
echo 'standard@evilcorp.com:5f4dcc3b5aa765d61d8327deb882cf99' > $test_dir/standard.bak
echo "INSERT INTO users VALUES ('sql1','sql1@evilcorp.com','5f4dcc3b5aa765d61d8327deb882cf99'), ('sql2','sql2@evilcorp.com','5f4dcc3b5aa765d61d8327deb882cf99'); notsql3:notsql3@evilcorp.com:Password" > $test_dir/deeper/sql
echo 'standard@evilcorp.com:5f4dcc3b5aa765d61d8327deb882cf99
standard2@evilcorp.com:5f4dcc3b5aa765d61d8327deb882cf99' > $test_dir/standard2