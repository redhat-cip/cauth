#!/usr/bin/env python
#
# Copyright (C) 2015 eNovance SAS <licensing@enovance.com>
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
try:
    import keystoneclient as kc
except ImportError:
    kc = None

from cauth.auth import base


"""password-based authentication plugins."""


logger = logging.getLogger(__name__)


class BasePasswordAuthPlugin(base.AuthProtocolPlugin):

    @classmethod
    def get_args(cls):
        return {'username': {'description': 'user login'},
                'password': {'description': 'user password'}}


class LocalUserAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the cauth config file.
    """

    _config_section = "users"

    def authenticate(self, **auth_context):
        username = auth_context.get('username', None)
        password = auth_context.get('password', None)
        user = self.conf.get(username)
        if user:
            salted_password = user.get('password')
            if salted_password == crypt.crypt(password, salted_password):
                return {'login': username,
                        'email': user.get('mail'),
                        'name': user.get('lastname'),
                        'ssh_keys': []}
        err = '%s not found in local config file' % username
        raise base.UnauthenticatedError(err)


class LDAPAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using an LDAP backend.
    """

    _config_section = "ldap"

    def authenticate(self, **auth_context):
        username = auth_context.get('username', None)
        password = auth_context.get('password', None)
        try:
            conn = ldap.initialize(self.conf['host'])
            conn.set_option(ldap.OPT_REFERRALS, 0)
        except ldap.LDAPError as e:
            logger.error('Client unable to bind on LDAP: %s' % e.message)
            raise base.UnauthenticatedError(e.message)
        if not password or not username:
            logger.error('Client unable to bind on LDAP empty credentials.')
            raise base.UnauthenticatedError('invalid credentials')
        who = self.conf['dn'] % {'username': username}
        try:
            conn.simple_bind_s(who, password)
        except (ldap.INVALID_CREDENTIALS, ldap.SERVER_DOWN):
            logger.error('Client unable to bind on LDAP invalid credentials.')
            raise base.UnauthenticatedError('invalid credentials')

        result = conn.search_s(who, ldap.SCOPE_SUBTREE, '(cn=*)',
                               attrlist=[self.conf['sn'], self.conf['mail']])
        if len(result) == 1:
            user = result[0]  # user is a tuple
            mail = user[1].get(self.conf['mail'], [None])
            lastname = user[1].get(self.conf['sn'], [None])
            return {'login': username,
                    'email': mail[0],
                    'name': lastname[0],
                    'ssh_keys': []}

        logger.error('LDAP client search failed')
        raise base.UnauthenticatedError('LDAP client search failed')


class ManageSFAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the ManageSF local db backend.
    """

    _config_section = "localdb"

    def authenticate(self, **auth_context):
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        bind_url = urllib.basejoin(self.conf['managesf_url'], '/manage/bind')
        headers = {"Authorization": encode(username, password)}
        response = requests.get(bind_url, headers=headers)

        if response.status_code > 399:
            logger.error('localdb auth failed: %s' % response)
            raise base.UnauthenticatedError(response)
        infos = response.json()
        return {'login': username,
                'email': infos['email'],
                'name': infos['fullname'],
                'ssh_keys': [{'key': infos['sshkey']}, ]}


class KeystoneAuthPlugin(BasePasswordAuthPlugin):
    """User authentication using the ManageSF local db backend.
    """

    _config_section = "keystone"

    def authenticate(self, **auth_context):
        """Authentication against a keystone server. We simply try to fetch an
        unscoped token."""
        username = auth_context.get('username', '')
        password = auth_context.get('password', '')
        auth_url = self.conf['auth_url']
        if kc:
            try:
                client = kc.client.Client(auth_url=auth_url,
                                          username=username,
                                          password=password)
                if client.authenticate():
                    # TODO(mhu) keystone can store a user's e-mail, but with
                    # default keystone policies this info can only be fetched
                    # by an admin account. Either patch keystone to allow
                    # a user to fetch her own info, or add admin auth to this
                    # plugin in order to fetch the e-mail.
                    return {'login': username,
                            'email': '',
                            'name': username,
                            'ssh_keys': []}
            except kc.exceptions.Unauthorized:
                msg = ("keystone authentication failed: "
                       "Invalid user or password")
                raise base.UnauthenticatedError(msg)
            except Exception as e:
                raise base.UnauthenticatedError("Unknown error: %s" % e)
        else:
            msg = "keystone authentication not available on this server"
            raise base.UnauthenticatedError(msg)
        # every other case
        msg = ("keystone authentication failed")
        raise base.UnauthenticatedError(msg)


class PasswordAuthPlugin(BasePasswordAuthPlugin):
    """Generic password authentication, using all the specific plugins.
    """

    _config_section = None

    def __init__(self, conf):
        self.plugins = []
        plugins_list = [LocalUserAuthPlugin,
                        LDAPAuthPlugin,
                        ManageSFAuthPlugin]
        if kc:
            plugins_list.append(KeystoneAuthPlugin)
        for plugin in plugins_list:
            try:
                self.plugins.append(plugin(conf))
            except base.AuthProtocolNotAvailableError:
                pass

    def configure_plugin(self, conf):
        pass

    def authenticate(self, **auth_context):
        user = None
        for plugin in self.plugins:
            try:
                user = plugin.authenticate(**auth_context)
            except base.UnauthenticatedError:
                pass
        if user:
            return user
        raise base.UnauthenticatedError('Password authentication failed')
