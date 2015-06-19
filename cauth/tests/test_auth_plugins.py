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
import json
import ldap
import tempfile
from unittest import TestCase

import httmock
from mock import patch, MagicMock
from pecan import configuration
import stevedore

from cauth.auth import base
from cauth.tests.common import FakeResponse, githubmock_request


SQL = {'url': 'sqlite:///%s' % tempfile.mkstemp()[1],
       'echo': False,
       'encoding': 'utf-8', }


TEST_LDAP_AUTH = {
    'host': 'my.ldap.url',
    'dn': 'uid=%(username)s,ou=test,dc=corp',
    'sn': 'sn',
    'mail': 'mail',
}


TEST_GITHUB_AUTH = {
    'top_domain': 'tests.dom',
    'auth_url':  'https://github.com/login/oauth/authorize',
    'redirect_uri': 'https://github/redirect/url',
    'client_id': 'your_github_app_id',
    'client_secret': 'your_github_app_secret',
}


TEST_USERS_AUTH = {
    "user1": {
        "lastname": "example user",
        "mail": "user@tests.dom",
        "password": crypt.crypt("userpass", "$6$EFeaxATWohJ"),
    },
}


TEST_LOCALDB_AUTH = {
    'managesf_url': 'https://tests.dom',
}


class BaseTestAuthPlugin(TestCase):
    def _load_auth_plugin(self, name, conf):
        return stevedore.DriverManager(
            namespace='cauth.authentication',
            name=name,
            invoke_on_load=True,
            invoke_args=(configuration.Config(conf),)).driver


class TestDrivers(BaseTestAuthPlugin):
    def test_load_plugins(self):
        """Test that the namespace and entry points are available"""
        for plugin in ('GithubPersonalAccessToken',
                       'Github',
                       'Password'):
            driver = stevedore.DriverManager(
                namespace='cauth.authentication',
                name=plugin).driver
            self.assertEqual(plugin + 'AuthPlugin',
                             driver.__name__)

    def test_instantiate_plugins(self):
        """Test that plugins can correctly be instantiated"""
        conf = {'auth': {
            'ldap': TEST_LDAP_AUTH,
            'github': TEST_GITHUB_AUTH,
            'localdb': TEST_LOCALDB_AUTH,
            'users': TEST_USERS_AUTH, }, }
        for plugin in ('GithubPersonalAccessToken',
                       'Github',
                       'Password'):
            driver = self._load_auth_plugin(plugin, conf)
            self.assertEqual(plugin + 'AuthPlugin',
                             driver.__class__.__name__)

    def test_no_config_for_plugin(self):
        """Test that plugin raises error if configuration cannot be found"""
        conf = {'auth': {}}
        with self.assertRaises(base.AuthProtocolNotAvailableError):
            self._load_auth_plugin('Github', conf)


class TestPasswordAuthPlugin(BaseTestAuthPlugin):
    def test_users_auth(self):
        """Test password authentication with local users only"""
        conf = {'auth': {'users': TEST_USERS_AUTH, }, }
        driver = self._load_auth_plugin('Password', conf)
        # assert the driver has loaded only one plugin
        self.assertEqual(1,
                         len(driver.plugins))
        self.assertEqual('LocalUserAuthPlugin',
                         driver.plugins[0].__class__.__name__)
        # test valid user
        auth_context = {'username': 'user1',
                        'password': 'userpass'}
        expected = {'login': 'user1',
                    'email': 'user@tests.dom',
                    'name': 'example user',
                    'ssh_keys': [], }
        authenticated = driver.authenticate(**auth_context)
        self.assertEqual(expected,
                         authenticated,
                         "Got %r" % authenticated)
        # test wrong user
        auth_context = {'username': 'nope',
                        'password': 'userpass'}
        with self.assertRaises(base.UnauthenticatedError):
            driver.authenticate(**auth_context)

    def test_localdb_auth(self):
        """Test password authentication with ManageSF users only"""
        conf = {'auth': {'localdb': TEST_LOCALDB_AUTH, }, }
        driver = self._load_auth_plugin('Password', conf)
        # assert the driver has loaded only one plugin
        self.assertEqual(1,
                         len(driver.plugins))
        self.assertEqual('ManageSFAuthPlugin',
                         driver.plugins[0].__class__.__name__)
        # test valid user
        auth_context = {'username': 'les',
                        'password': 'userpass'}
        expected = {'login': 'les',
                    'email': 'les@primus.com',
                    'name': 'Les Claypool',
                    'ssh_keys': [{'key': 'Jerry was a race car driver'}, ], }
        with patch('requests.get') as g:
            _response = {'username': 'les',
                         'fullname': 'Les Claypool',
                         'email': 'les@primus.com',
                         'sshkey': 'Jerry was a race car driver'}
            g.return_value = FakeResponse(200, json.dumps(_response), True)
            authenticated = driver.authenticate(**auth_context)
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)
        # test wrong user
        auth_context = {'username': 'nope',
                        'password': 'userpass'}
        with patch('requests.get') as g:
            g.return_value = FakeResponse(401, 'Unauthorized')
            with self.assertRaises(base.UnauthenticatedError):
                driver.authenticate(**auth_context)

    def test_ldap_auth(self):
        """Test password authentication against LDAP backend only"""
        conf = {'auth': {'ldap': TEST_LDAP_AUTH, }, }
        driver = self._load_auth_plugin('Password', conf)
        # assert the driver has loaded only one plugin
        self.assertEqual(1,
                         len(driver.plugins))
        self.assertEqual('LDAPAuthPlugin',
                         driver.plugins[0].__class__.__name__)
        # test valid user
        auth_context = {'username': 'Kenny',
                        'password': 'McCormick'}
        expected = {'login': 'Kenny',
                    'email': 'princesskenny@southpark.com',
                    'name': 'Purinsesu Kenny',
                    'ssh_keys': [], }
        with patch('ldap.initialize') as fake_init:
            conn = MagicMock()
            fake_init.return_value = conn
            conn.search_s.return_value = [(0,
                                           {'mail': [expected['email'], ],
                                            'sn': [expected['name'], ], }), ]

            authenticated = driver.authenticate(**auth_context)
            conn.simple_bind_s.assert_called_with(
                TEST_LDAP_AUTH['dn'] % {'username': 'Kenny'},
                'McCormick')
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)
        # test invalid user
        with patch('ldap.initialize') as fake_init:
            conn = MagicMock()
            fake_init.return_value = conn
            conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
            with self.assertRaises(base.UnauthenticatedError):
                driver.authenticate(**auth_context)

    def test_auth(self):
        """Test password authentication with every backend activated"""
        conf = {'auth': {'ldap': TEST_LDAP_AUTH,
                         'localdb': TEST_LOCALDB_AUTH,
                         'users': TEST_USERS_AUTH, }, }
        driver = self._load_auth_plugin('Password', conf)
        # assert the driver has loaded every plugin
        self.assertEqual(3,
                         len(driver.plugins))
        # test wrong user
        auth_context = {'username': 'nope',
                        'password': 'userpass'}
        with patch('ldap.initialize') as fake_init:
            conn = MagicMock()
            fake_init.return_value = conn
            conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
            with patch('requests.get') as g:
                g.return_value = FakeResponse(401, 'Unauthorized')
                with self.assertRaises(base.UnauthenticatedError):
                    driver.authenticate(**auth_context)
                # test valid user
                auth_context = {'username': 'user1',
                                'password': 'userpass'}
                expected = {'login': 'user1',
                            'email': 'user@tests.dom',
                            'name': 'example user',
                            'ssh_keys': [], }
                authenticated = driver.authenticate(**auth_context)
                self.assertEqual(expected,
                                 authenticated,
                                 "Got %r" % authenticated)
            # test authentication successful on ManageSF
            with patch('requests.get') as g:
                auth_context = {'username': 'les',
                                'password': 'userpass'}
                ssh = {'key': 'Jerry was a race car driver'}
                expected = {'login': 'les',
                            'email': 'les@primus.com',
                            'name': 'Les Claypool',
                            'ssh_keys': [ssh, ], }
                _response = {'username': 'les',
                             'fullname': 'Les Claypool',
                             'email': 'les@primus.com',
                             'sshkey': 'Jerry was a race car driver'}
                g.return_value = FakeResponse(200,
                                              json.dumps(_response),
                                              True)
                authenticated = driver.authenticate(**auth_context)
                self.assertEqual(expected,
                                 authenticated,
                                 "Got %r" % authenticated)


class TestGithubOrganizations(BaseTestAuthPlugin):
    def setUp(self):
        conf = {'auth': {'github': TEST_GITHUB_AUTH, }, }
        conf['auth']['github']['allowed_organizations'] = 'eNovance'
        self.driver = self._load_auth_plugin('Github', conf)

    def test_allowed_organizations(self):
        """Test checking allowed organizations"""
        with patch('requests.get') as g:
            g.return_value.json.return_value = [{'login': 'eNovance'}, ]
            self.assertTrue(self.driver.organization_allowed('token'))
        with patch('requests.get') as g:
            g.return_value.json.return_value = [{'login': 'acme'}, ]
            self.assertFalse(self.driver.organization_allowed('token'))

    def tearDown(self):
        if 'allowed_organizations' in TEST_GITHUB_AUTH:
            del TEST_GITHUB_AUTH['allowed_organizations']


class TestGithubAuthPlugin(BaseTestAuthPlugin):
    def setUp(self):
        conf = {'auth': {'github': TEST_GITHUB_AUTH, }, }
        self.driver = self._load_auth_plugin('Github', conf)

    def test_redirect(self):
        """Test that user is redirected"""
        response = MagicMock()
        auth_context = {'back': '/',
                        'response': response}
        with patch('cauth.model.db.put_url'):
            self.driver.authenticate(**auth_context)
            self.assertEqual(302,
                             response.status_code)

    def test_get_access_token(self):
        """Test fetching access token from github"""
        _token = "TOKEN"
        token = {'access_token': _token, }
        with patch('requests.post') as p:
            p.return_value = FakeResponse(200,
                                          json.dumps(token),
                                          True)
            returned_token = self.driver.get_access_token('boop')
            self.assertEqual(_token,
                             returned_token)

    def test_callback(self):
        """Test successful callback from Github"""
        auth_context = {'state': 'test_state',
                        'code': 'user6_code', }
        expected = {'login': 'user6',
                    'email': 'user6@tests.dom',
                    'name': 'Demo user6',
                    'ssh_keys': {'key': ''}}
        with httmock.HTTMock(githubmock_request):
            authenticated = self.driver.authenticate(**auth_context)
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)

    def test_failed_auth(self):
        """Test Github auth failures"""
        auth_context = {'state': 'test_state',
                        'code': 'OMGHAX', }
        with httmock.HTTMock(githubmock_request):
            with self.assertRaises(base.UnauthenticatedError):
                self.driver.authenticate(**auth_context)
        with self.assertRaises(base.UnauthenticatedError):
            auth_context = {'error': 'OMG',
                            'error_description': 'No luck'}
            self.driver.authenticate(**auth_context)


class TestGithubPersonalAccessTokenAuthPlugin(BaseTestAuthPlugin):
    def setUp(self):
        conf = {'auth': {'github': TEST_GITHUB_AUTH, }, }
        self.driver = self._load_auth_plugin('GithubPersonalAccessToken', conf)

    def test_authenticate(self):
        """Test authentication with a personal access token from Github"""
        with httmock.HTTMock(githubmock_request):
            auth_context = {'token': 'user6_token'}
            expected = {'login': 'user6',
                        'email': 'user6@tests.dom',
                        'name': 'Demo user6',
                        'ssh_keys': {'key': ''}}
            authenticated = self.driver.authenticate(**auth_context)
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)
