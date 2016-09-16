# -*- coding: utf-8 -*-
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
import json
import ldap
import tempfile
from unittest import TestCase

import keystoneclient.exceptions as k_exc
import httmock
from mock import patch, MagicMock
from pecan import configuration
import stevedore

from cauth.auth import base
from cauth.tests.common import FakeResponse, githubmock_request
from cauth.tests.common import openid_identity


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
    'redirect_uri': 'https://fqdn/auth/login/oauth2/callback',
    'client_id': 'your_github_app_id',
    'client_secret': 'your_github_app_secret',
}


TEST_GOOGLE_AUTH = {
    'redirect_uri': 'https://fqdn/auth/login/oauth2/callback',
    'client_id': 'your_google_app_id',
    'client_secret': 'your_google_app_secret',
}


TEST_BITBUCKET_AUTH = {
    'redirect_uri': 'https://fqdn/auth/login/oauth2/callback',
    'client_id': 'your_bitbucket_app_id',
    'client_secret': 'your_bitbucket_app_secret',
}


TEST_OPENID_AUTH = {
    'auth_url': 'https://my.openid.provider/+openid',
    'redirect_uri': '/auth/login/openid/callback',
}


TEST_USERS_AUTH = {
    "user1": {
        "lastname": "example user",
        "mail": "user@tests.dom",
        "password": crypt.crypt("userpass", "$6$EFeaxATWohJ"),
    },
    "user2": {
        "lastname": "example user2",
        "mail": "user2@tests.dom",
        "password": crypt.crypt("utéf8", "$6$EFeaxATWohJ"),
    },
}


TEST_LOCALDB_AUTH = {
    'managesf_url': 'https://tests.dom',
}


TEST_KEYSTONE_AUTH = {
    'auth_url': 'http://keystone.server:5000/v2.0',
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
            'google': TEST_GOOGLE_AUTH,
            'bitbucket': TEST_BITBUCKET_AUTH,
            'localdb': TEST_LOCALDB_AUTH,
            'users': TEST_USERS_AUTH,
            'keystone': TEST_KEYSTONE_AUTH, }, }
        for plugin in ('GithubPersonalAccessToken',
                       'Github',
                       'Google',
                       'BitBucket',
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
                    'ssh_keys': [],
                    'external_auth': {'domain': 'CAUTH_CONF',
                                      'external_id': 'user1'}}
        authenticated = driver.authenticate(**auth_context)
        self.assertEqual(expected,
                         authenticated,
                         "Got %r" % authenticated)
        # test valid user with utf8 char in passord
        auth_context = {'username': 'user2',
                        'password': 'utéf8'}
        expected = {'login': 'user2',
                    'email': 'user2@tests.dom',
                    'name': 'example user2',
                    'ssh_keys': [],
                    'external_auth': {'domain': 'CAUTH_CONF',
                                      'external_id': 'user2'}}
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
        d = TEST_LOCALDB_AUTH['managesf_url']
        expected = {'login': 'les',
                    'email': 'les@primus.com',
                    'name': 'Les Claypool',
                    'ssh_keys': [{'key': 'Jerry was a race car driver'}, ],
                    'external_auth': {'domain': d,
                                      'external_id': 'les'}}
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
        # test unicode username
        auth_context = {'username': u'自来也',
                        'password': 'userpass'}
        expected = {'login': u'自来也',
                    'email': 'rasengan@sennin.com',
                    'name': 'The Gallant Jiraiya',
                    'ssh_keys': [{'key': 'Icha Icha Paradise'}, ],
                    'external_auth': {'domain': d,
                                      'external_id': u'自来也'}}
        with patch('requests.get') as g:
            _response = {'username': u'自来也',
                         'fullname': 'The Gallant Jiraiya',
                         'email': 'rasengan@sennin.com',
                         'sshkey': 'Icha Icha Paradise'}
            g.return_value = FakeResponse(200, json.dumps(_response), True)
            authenticated = driver.authenticate(**auth_context)
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)

    def test_keystone_auth(self):
        """Test password authentication with keystone only"""
        conf = {'auth': {'keystone': TEST_KEYSTONE_AUTH, }, }
        driver = self._load_auth_plugin('Password', conf)
        # assert the driver has loaded only one plugin
        self.assertEqual(1,
                         len(driver.plugins))
        self.assertEqual('KeystoneAuthPlugin',
                         driver.plugins[0].__class__.__name__)
        # test valid user
        auth_context = {'username': 'openstack',
                        'password': 'liberty'}
        expected = {'login': 'openstack',
                    'email': '',
                    'name': 'openstack',
                    'ssh_keys': [],
                    'external_auth': {'domain': TEST_KEYSTONE_AUTH['auth_url'],
                                      'external_id': 1234}}
        with patch('keystoneclient.client.Client') as c:
            client = MagicMock()
            client.authenticate.return_value = True
            client.user_id = 1234
            c.return_value = client
            authenticated = driver.authenticate(**auth_context)
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)
        # test wrong user
        auth_context = {'username': 'nope',
                        'password': 'userpass'}
        with patch('keystoneclient.client.Client') as c:
            client = MagicMock()
            client.authenticate.side_effect = k_exc.Unauthorized
            c.return_value = client
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
        who = TEST_LDAP_AUTH['dn'] % {'username': 'Kenny'}
        expected = {'login': 'Kenny',
                    'email': 'princesskenny@southpark.com',
                    'name': 'Purinsesu Kenny',
                    'ssh_keys': [],
                    'external_auth': {'domain': TEST_LDAP_AUTH['host'],
                                      'external_id': who}}
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
                         'users': TEST_USERS_AUTH,
                         'keystone': TEST_KEYSTONE_AUTH, }, }
        driver = self._load_auth_plugin('Password', conf)
        # assert the driver has loaded every plugin
        self.assertEqual(4,
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
                            'ssh_keys': [],
                            'external_auth': {'domain': 'CAUTH_CONF',
                                              'external_id': 'user1'}}
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
                            'ssh_keys': [ssh, ],
                            'external_auth': {'domain': 'https://tests.dom',
                                              'external_id': 'les'}}
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
                        'code': 'user6_code',
                        'calling_back': True}
        expected = {'login': 'user6',
                    'email': 'user6@tests.dom',
                    'name': 'Demo user6',
                    'ssh_keys': {'key': ''},
                    'external_auth': {'domain': self.driver.auth_url,
                                      'external_id': 666}}
        with httmock.HTTMock(githubmock_request):
            authenticated = self.driver.authenticate(**auth_context)
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)

    def test_failed_auth(self):
        """Test Github auth failures"""
        auth_context = {'state': 'test_state',
                        'code': 'OMGHAX',
                        'calling_back': True}
        with httmock.HTTMock(githubmock_request):
            with self.assertRaises(base.UnauthenticatedError):
                self.driver.authenticate(**auth_context)
        with self.assertRaises(base.UnauthenticatedError):
            auth_context = {'error': 'OMG',
                            'error_description': 'No luck',
                            'calling_back': True}
            self.driver.authenticate(**auth_context)


class TestGoogleAuthPlugin(BaseTestAuthPlugin):
    def setUp(self):
        conf = {'auth': {'google': TEST_GOOGLE_AUTH, }, }
        self.driver = self._load_auth_plugin('Google', conf)
        self.gplus_output = {"kind": "plus#person",
                             "etag": "\"xw0en60W6-NurXn4VBU-CMjSPEw/2\"",
                             "nickname": "dio",
                             "gender": "male",
                             "emails": [{"value": "dio.brando@warudo.com",
                                         "type": "account"}],
                             "objectType": "person",
                             "id": "999999",
                             "displayName": "Dio Brando (dio)",
                             "name": {"familyName": "Brando",
                                      "givenName": "Dio"},
                             "url": "https://plus.google.com/999999",
                             "image": {"url": "https://wryyyy",
                                       "isDefault": False},
                             "isPlusUser": True,
                             "language": "fr",
                             "circledByCount": 18,
                             "verified": False}

    def test_get_user_data(self):
        """Test fetching user data from google apis."""
        google_output = json.dumps(self.gplus_output)
        with patch('requests.get') as get:
            get.return_value = FakeResponse(200,
                                            content=google_output,
                                            is_json=True)
            user = self.driver.get_user_data(token='MYTOKEN')
            get.assert_called_with("https://www.googleapis.com/plus/"
                                   "v1/people/me?access_token=MYTOKEN")
            self.assertEqual("dio.brando",
                             user.get('login'))
            self.assertEqual("Dio Brando",
                             user.get('name'))
            self.assertEqual("dio.brando@warudo.com",
                             user.get('email'))
            self.assertEqual([],
                             user.get('ssh_keys'))
            self.assertEqual("https://accounts.google.com/o/oauth2/v2/auth",
                             user.get('external_auth', {}).get('domain'))
            self.assertEqual("999999",
                             user.get('external_auth', {}).get('external_id'))


class TestBitBucketAuthPlugin(BaseTestAuthPlugin):
    def setUp(self):
        conf = {'auth': {'bitbucket': TEST_BITBUCKET_AUTH, }, }
        self.driver = self._load_auth_plugin('BitBucket', conf)

    def test_get_user_data(self):
        """Test fetching user data from google apis."""
        def fake_get(url, *args, **kwargs):
            if "user?" in url:
                data = {"created_on": "2016-08-01T15:03:12.323022+00:00",
                        "display_name": "Joseph Joestar",
                        "links": {"avatar": {"href": "https://bleh"},
                                  "followers": {"href": "https://bleh"},
                                  "following": {},
                                  "hooks": {},
                                  "html": {},
                                  "repositories": {},
                                  "self": {},
                                  "snippets": {}},
                        "location": None,
                        "type": "user",
                        "username": "JoJo",
                        "uuid": "{e6193115-45aa-454f-8d4b-03b4fb2d2083}",
                        "website": None}
            elif "emails?" in url:
                data = {"page": 1,
                        "pagelen": 10,
                        "size": 1,
                        "values": [{"email": "joestar@speedwagon.com",
                                    "is_confirmed": True,
                                    "is_primary": True,
                                    "links": {"self": {"href": "bleh"}},
                                    "type": "email"}]}
            elif "ssh" in url:
                data = [{"pk": 171052,
                         "key": "ssh-rsa AAAAB3NzaC",
                         "label": "home"}]
            else:
                data = url
            return FakeResponse(200,
                                content=json.dumps(data),
                                is_json=True)

        with patch('requests.get') as get:
            get.side_effect = fake_get
            user = self.driver.get_user_data(token='MYTOKEN')
            self.assertEqual("JoJo",
                             user.get('login'))
            self.assertEqual("Joseph Joestar",
                             user.get('name'))
            self.assertEqual("joestar@speedwagon.com",
                             user.get('email'))
            self.assertEqual([{'key': "ssh-rsa AAAAB3NzaC"}],
                             user.get('ssh_keys'))
            self.assertEqual('https://bitbucket.org/site/oauth2/authorize',
                             user.get('external_auth', {}).get('domain'))
            self.assertEqual("e6193115-45aa-454f-8d4b-03b4fb2d2083",
                             user.get('external_auth', {}).get('external_id'))


class TestOpenIDAuthPlugin(BaseTestAuthPlugin):
    def setUp(self):
        conf = {'auth': {'openid': TEST_OPENID_AUTH, }, }
        self.driver = self._load_auth_plugin('OpenID', conf)

    def test_redirect(self):
        """Test that user is redirected"""
        response = MagicMock()
        auth_context = {'back': '/',
                        'response': response}
        with patch('cauth.auth.openid.request') as r:
            r.host_url = 'tests.dom'
            self.driver.authenticate(**auth_context)
            self.assertEqual(302, response.status_code)

    def test_verify_data(self):
        """Validate the data from the OpenID provider"""
        with patch('requests.post') as p:
            p.return_value = FakeResponse(200,
                                          content="is_valid:true ns:http")
            self.assertEqual(None,
                             self.driver.verify_data(openid_identity))
            with self.assertRaises(base.UnauthenticatedError):
                o = openid_identity.copy()
                del o['openid.sreg.nickname']
                self.driver.verify_data(o)
        with patch('requests.post') as p:
            p.return_value = FakeResponse(401,
                                          content="")
            with self.assertRaises(base.UnauthenticatedError):
                self.driver.verify_data(openid_identity)
        with patch('requests.post') as p:
            p.return_value = FakeResponse(200,
                                          content="is_valid:false ns:http")
            with self.assertRaises(base.UnauthenticatedError):
                self.driver.verify_data(openid_identity)

    def test_callback(self):
        """Test successful callback from OpenID provider"""
        auth_context = openid_identity.copy()
        auth_context['response'] = MagicMock()
        auth_context['back'] = '/'
        i = openid_identity['openid.claimed_id']
        expected = {'login': 'NickyNicky',
                    'email': 'testy@test.com',
                    'name': 'Nick McTesty',
                    'ssh_keys': [],
                    'external_auth': {'domain': TEST_OPENID_AUTH['auth_url'],
                                      'external_id': i}}
        with patch('requests.post') as p:
            p.return_value = FakeResponse(200,
                                          content="is_valid:true ns:http")
            with patch('cauth.auth.openid.request') as r:
                r.host_url = 'tests.dom'
                authenticated = self.driver._authenticate(**auth_context)
                self.assertEqual(expected,
                                 authenticated,
                                 "Got %r, expected %r" % (authenticated,
                                                          expected))


class TestGithubPersonalAccessTokenAuthPlugin(BaseTestAuthPlugin):
    def setUp(self):
        conf = {'auth': {'github': TEST_GITHUB_AUTH, }, }
        self.driver = self._load_auth_plugin('GithubPersonalAccessToken', conf)

    def test_authenticate(self):
        """Test authentication with a personal access token from Github"""
        with httmock.HTTMock(githubmock_request):
            auth_context = {'token': 'user6_token'}
            d = self.driver.auth_url
            expected = {'login': 'user6',
                        'email': 'user6@tests.dom',
                        'name': 'Demo user6',
                        'ssh_keys': {'key': ''},
                        'external_auth': {'domain': d,
                                          'external_id': 666}}
            authenticated = self.driver.authenticate(**auth_context)
            self.assertEqual(expected,
                             authenticated,
                             "Got %r" % authenticated)
