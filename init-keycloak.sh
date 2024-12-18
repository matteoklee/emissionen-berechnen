#!/bin/bash

until curl -s http://localhost:8086 > /dev/null; do
  echo "Waiting for Keycloak to be available..."
  sleep 5
done

cd /opt/keycloak/bin

./kcadm.sh config credentials --server http://localhost:8086 --realm master --user admin --password admin

./kcadm.sh update realms/master -s sslRequired=NONE

echo "Keycloak initialization completed!"