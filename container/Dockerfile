ARG HA_IMAGE=ghcr.io/home-assistant/home-assistant:2026.2.3
FROM ${HA_IMAGE}

RUN python3 -m pip install --no-cache-dir --break-system-packages 'ldap3'

COPY ldap-auth.py /usr/local/bin/homeassistant-ucs-ldap-auth
RUN chmod 0755 /usr/local/bin/homeassistant-ucs-ldap-auth
