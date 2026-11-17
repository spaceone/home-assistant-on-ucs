#!/usr/bin/env python3
"""Authenticate a Home Assistant command-line login against UCS LDAP."""

import json
import logging
import os
import sys
from pathlib import Path

from ldap3 import Connection, Server, SUBTREE, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
import ssl

CONFIG = Path('/etc/home-assistant-ucs/ldap.json')
LOG = logging.getLogger('homeassistant-ucs-ldap')


def verify_group(connection, group_dn, user_dn, attribute):
    if attribute not in ('uniqueMember', 'member', 'memberUid'):
        raise ValueError('unsupported LDAP group membership attribute')
    connection.search(group_dn, '(objectClass=*)', search_scope='BASE', attributes=[attribute])
    if not connection.entries:
        return False
    values = [str(v) for v in connection.entries[0][attribute].values]
    if attribute == 'memberUid':
        return False
    return user_dn.casefold() in {v.casefold() for v in values}


def main():
    cfg = json.loads(CONFIG.read_text(encoding='utf-8'))
    username = os.environ.get('username', '').strip()
    password = os.environ.get('password', '')
    if not cfg.get('enabled') or not username or not password or '\x00' in username:
        return 1
    if not cfg.get('bind_dn'):
        raise ValueError('missing LDAP bind DN')
    if not Path(cfg['bind_secret_file']).is_file():
        raise ValueError('LDAP bind password file unavailable')
    bind_secret = Path(cfg['bind_secret_file']).read_text().strip()
    if not bind_secret:
        raise ValueError('LDAP bind password empty')
    timeout = cfg.get('timeout_seconds', 8)
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg['ca_file'])
    server = Server(cfg['host'], port=cfg['port'], use_ssl=(cfg['security'] == 'ldaps'), tls=tls, connect_timeout=timeout, get_info=None)
    conn = Connection(server, user=cfg['bind_dn'], password=bind_secret, auto_bind=False, receive_timeout=timeout, raise_exceptions=True)
    try:
        conn.open()
        if cfg['security'] == 'starttls' and not conn.start_tls():
            return 1
        if not conn.bind():
            return 1
        filter_value = cfg['user_filter'].replace('{username}', escape_filter_chars(username))
        conn.search(cfg['base_dn'], filter_value, search_scope=SUBTREE, attributes=['cn', 'displayName', 'givenName', 'sn'])
        if len(conn.entries) != 1:
            return 1
        entry = conn.entries[0]
        user_dn = str(entry.entry_dn)
        display_name = str(entry['displayName'].value or entry['cn'].value or username)
        user_ok = verify_group(conn, cfg['user_group'], user_dn, cfg['group_member_attribute'])
        admin_ok = verify_group(conn, cfg['admin_group'], user_dn, cfg['group_member_attribute'])
        if not (user_ok or admin_ok):
            return 1
    finally:
        conn.unbind()
    # only authenticate the user after group membership has been checked
    user_conn = Connection(server, user=user_dn, password=password, auto_bind=False, receive_timeout=timeout, raise_exceptions=True)
    try:
        user_conn.open()
        if cfg['security'] == 'starttls' and not user_conn.start_tls():
            return 1
        if not user_conn.bind():
            return 1
    finally:
        user_conn.unbind()
    name = display_name
    name = ''.join(x for x in name if x not in '\r\n')
    print('name = ' + name)
    print('group = system-admin' if admin_ok else 'group = system-users')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (LDAPException, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        LOG.error('LDAP authentication failed: %s', type(exc).__name__)
        sys.exit(1)
