#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import crypt
import ldap
import logging
import requests
import urllib

from basicauth import encode

logger = logging.getLogger(__name__)


def check_static_user(config, username, password):
    user = config.auth.get('users', {}).get(username)
    if user:
        salted_password = user.get('password')
        if salted_password == crypt.crypt(password, salted_password):
            return user.get('mail'), user.get('lastname'), []


def check_db_user(config, username, password):
    localdb = config.auth.get('localdb')
    if localdb:
        bind_url = urllib.basejoin(localdb['managesf_url'], '/manage/bind')
        headers = {"Authorization": encode(username, password)}
        response = requests.get(bind_url, headers=headers)

        if response.status_code > 399:
            logger.error('localdb auth failed: %s' % response)
            return None
        infos = response.json()
        return infos['email'], infos['fullname'], [{'key': infos['sshkey']}, ]


def check_ldap_user(config, username, password):
    config = config.auth.ldap
    try:
        conn = ldap.initialize(config['host'])
        conn.set_option(ldap.OPT_REFERRALS, 0)
    except ldap.LDAPError:
        logger.error('Client unable to bind on LDAP unexpected behavior.')
        return None

    who = config['dn'] % {'username': username}
    try:
        conn.simple_bind_s(who, password)
    except (ldap.INVALID_CREDENTIALS, ldap.SERVER_DOWN):
        logger.error('Client unable to bind on LDAP invalid credentials.')
        return None

    result = conn.search_s(who, ldap.SCOPE_SUBTREE, '(cn=*)',
                           attrlist=[config['sn'], config['mail']])
    if len(result) == 1:
        user = result[0]  # user is a tuple
        mail = user[1].get(config['mail'], [None])
        lastname = user[1].get(config['sn'], [None])
        return mail[0], lastname[0], []

    logger.error('LDAP client search failed')
    return None
