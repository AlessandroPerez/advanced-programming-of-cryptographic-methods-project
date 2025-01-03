#!/bin/bash

original_dir=$(pwd)
script_dir=$(dirname "$0")

cd "$script_dir"

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -config openssl.cnf

cd "$original_dir"
