#!/usr/bin/sh

chmod u+x ./config/update_server_keys/target/release/update_server_keys
chmod u+x ./server/target/release/server

./config/update_server_keys/target/release/update_server_keys
./server/target/release/server


