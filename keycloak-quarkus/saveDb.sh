#!/usr/bin/env bash
set -e

kc_ver='25.0.2'
kc_dir="target/keycloak/keycloak-$kc_ver"
timestamp="$(date +%Y%m%d-%H%M%S)"

cd ../keycloak-quarkus

mv data "data.$timestamp"
mkdir data
cp -r "${kc_dir}/data/h2" data/h2
cp -r "${kc_dir}/conf/cache-ispn.xml" data/
cp -r "${kc_dir}/conf/keycloak.conf" data/
cp -r "${kc_dir}/config/radius.config" data/
mv "data.$timestamp/providers" data/