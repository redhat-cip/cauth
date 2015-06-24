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

from unittest import TestCase
from mock import patch
from M2Crypto import RSA, BIO

from webtest import TestApp
from pecan import load_app

from cauth.utils import common
from cauth.tests.common import dummy_conf, FakeResponse, githubmock_request

import os

import httmock
import urlparse


def raise_(ex):
    raise ex


def redmine_create_user_mock(*args, **kwargs):
    assert 'data' in kwargs
    assert 'X-Redmine-API-Key' in kwargs['headers']
    return FakeResponse(200)


def gen_rsa_key():
    conf = dummy_conf()
    if not os.path.isfile(conf.app['priv_key_path']):
        key = RSA.gen_key(2048, 65537, callback=lambda x, y, z: None)
        memory = BIO.MemoryBuffer()
        key.save_key_bio(memory, cipher=None)
        p_key = memory.getvalue()
        file(conf.app['priv_key_path'], 'w').write(p_key)


class FunctionalTest(TestCase):
    def setUp(self):
        c = dummy_conf()
        gen_rsa_key()
        config = {'redmine': c.redmine,
                  'gerrit': c.gerrit,
                  'app': c.app,
                  'auth': c.auth,
                  'services': c.services,
                  'sqlalchemy': c.sqlalchemy}
        # deactivate loggin that polute test output
        # even nologcapture option of nose effetcs
        # 'logging': c.logging}
        self.app = TestApp(load_app(config))

    def tearDown(self):
        pass


class TestUtils(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()
        gen_rsa_key()

    @classmethod
    def tearDownClass(cls):
        pass

    def test_signature(self):
        self.assertIsNot(None, common.signature('data'))

    def test_pre_register_user(self):
        p = 'cauth.utils.userdetails.UserDetailsCreator.create_user'
        with patch(p) as cu:
            common.pre_register_user({'login': 'john'})
            cu.assert_called_once_with(
                {'login': 'john',
                 'email': 'john@%s' % self.conf.app['cookie_domain'],
                 'name': 'User john'})

    def test_create_ticket(self):
        with patch('cauth.utils.common.signature') as sign:
            sign.return_value = '123'
            self.assertEqual('a=arg1;b=arg2;sig=123',
                             common.create_ticket(a='arg1', b='arg2'))


class TestCauthApp(FunctionalTest):
    def test_get_login(self):
        response = self.app.get('/login', params={'back': 'r/'})
        self.assertGreater(response.body.find('value="r/"'), 0)
        self.assertGreater(response.body.find('/auth/login/github?back=r/'), 0)
        self.assertEqual(response.status_int, 200)

    def test_post_login(self):
        # Ldap and Gitub Oauth backend are mocked automatically
        # if the domain is tests.dom
        with patch('cauth.service.gerrit.requests'):
            with patch('requests.get'):
                response = self.app.post('/login',
                                         params={'username': 'user1',
                                                 'password': 'userpass',
                                                 'back': 'r/'})
        self.assertEqual(response.status_int, 303)
        self.assertEqual('http://localhost/r/', response.headers['Location'])
        self.assertIn('Set-Cookie', response.headers)
        with patch('requests.get'):
            # baduser is not known from the mocked backend
            with patch('cauth.utils.userdetails'):
                response = self.app.post('/login',
                                         params={'username': 'baduser',
                                                 'password': 'userpass',
                                                 'back': 'r/'},
                                         status="*")
            self.assertEqual(response.status_int, 401)

            # Try with no creds
            with patch('cauth.utils.userdetails'):
                response = self.app.post('/login', params={'back': 'r/'},
                                         status="*")
            self.assertEqual(response.status_int, 401)

    def test_github_login(self):
        with httmock.HTTMock(githubmock_request):
            with patch('cauth.utils.userdetails'):
                response = self.app.get('/login/github/index',
                                        params={'username': 'user6',
                                                'back': 'r/',
                                                'password': 'userpass'})
                self.assertEqual(response.status_int, 302)
                parsed = urlparse.urlparse(response.headers['Location'])
                parsed_qs = urlparse.parse_qs(parsed.query)
                self.assertEqual('https', parsed.scheme)
                self.assertEqual('github.com', parsed.netloc)
                self.assertEqual('/login/oauth/authorize', parsed.path)
                self.assertEqual(
                    ['user:email, read:public_key, read:org'],
                    parsed_qs.get('scope'))
                self.assertEqual(
                    ['http://tests.dom/auth/login/github/callback"'],
                    parsed_qs.get('redirect_uri'))

    def test_get_logout(self):
        # Ensure client SSO cookie content is deleted
        response = self.app.get('/logout')
        self.assertEqual(response.status_int, 200)
        self.assertTrue('auth_pubtkt=;' in response.headers['Set-Cookie'])
        self.assertGreater(response.body.find(common.LOGOUT_MSG), 0)

    def test_introspection(self):
        response = self.app.get('/about/').json
        self.assertEqual('cauth',
                         response['service']['name'])
        self.assertEqual(set(['Password',
                              'Github',
                              'GithubPersonalAccessToken']),
                         set(response['service']['auth_methods']))
