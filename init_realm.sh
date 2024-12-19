#!/bin/bash

echo "Waiting for Realm to identify..."
sleep 5

docker exec -it emissionen-berechnen-keycloak-1 /bin/bash -c '
cd /opt/keycloak/bin
./kcadm.sh config credentials --server http://localhost:8080 --realm emissionen-berechnen-realm --user admin --password admin
./kcadm.sh update realms/emissionen-berechnen-realm -s sslRequired=NONE
'

echo "Keycloak initialization completed!"
