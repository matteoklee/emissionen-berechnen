#!/bin/bash

echo "Waiting for Keycloak to start..."
sleep 5

docker exec -it emissionen-berechnen-keycloak-1 /bin/bash -c '
cd /opt/keycloak/bin
./kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin
./kcadm.sh update realms/master -s sslRequired=NONE
'

echo "Keycloak initialization completed!"
