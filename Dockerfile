FROM quay.io/keycloak/keycloak:20.0.5

COPY init-keycloak.sh /opt/keycloak/

USER root
RUN chmod +x /opt/keycloak/init-keycloak.sh
USER 1000

CMD ["/bin/sh", "-c", "/opt/keycloak/init-keycloak.sh && /opt/keycloak/bin/kc.sh start-dev --http-enabled=true --hostname-strict=false --hostname-strict-https=false"]
