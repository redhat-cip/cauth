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

import base64
import crypt
import json
import os
import tempfile

import httmock
import urlparse


class FakeResponse():
    def __init__(self, code, content=None, is_json=False):
        self.status_code = code
        self.content = content
        self._json = {}
        if is_json and content:
            self._json = json.loads(content)

    def json(self, *args, **kwargs):
        return self._json


@httmock.urlmatch(netloc=r'(.*\.)?github\.com$')
def githubmock_request(url, request):
    users = {
        "user6": {"login": "user6",
                  "password": "userpass",
                  "email": "user6@tests.dom",
                  "name": "Demo user6",
                  "ssh_keys": "",
                  "code": "user6_code",
                  "token": "user6_token"}
    }

    headers = {'content-type': 'application/json'}

    # Handle a token request
    if request.method == 'POST':
        token = None
        code = urlparse.parse_qs(url.query)['code'][0]
        for user in users:
            if users[user]['code'] == code:
                token = users[user]['token']
                break
        if token:
            content = {"access_token": token}
        else:
            return httmock.response(401, {'Error': 'Not Found'})
    # Handle informations request
    else:
        u = None
        for user in users:
            auth_header = request.headers['Authorization']
            _token = users[user]['token']
            # handle oauth
            if _token in auth_header:
                u = user
                break
            # handle API key auth
            elif base64.b64encode(_token + ':x-oauth-basic') in auth_header:
                u = user
                break
        if not u:
            # user not found, do not authorize
            error_content = {u'message': u'Bad credentials'}

            return httmock.response(401, error_content)
        if 'keys' in url.path:
            content = {'key': users[u]['ssh_keys']}
        else:
            content = {'login': u,
                       'email': users[u]['email'],
                       'name': users[u]['name']}
    return httmock.response(200, content, headers, None, 5, request)


class dummy_conf():
    def __init__(self):
        self.redmine = {'apikey': 'XXX',
                        'apihost': 'api-redmine.test.dom',
                        'apiurl': 'http://api-redmine.test.dom',
                        }
        self.gerrit = {'url': 'XXX',
                       'admin_user': 'admin',
                       'admin_password': 'wxcvbn',
                       'db_host': 'mysql.tests.dom',
                       'db_name': 'gerrit',
                       'db_user': 'gerrit',
                       'db_password': 'wxcvbn',
                       }
        self.app = {'priv_key_path': '/tmp/priv_key',
                    'cookie_domain': 'tests.dom',
                    'cookie_period': 3600,
                    'root': 'cauth.controllers.root.RootController',
                    'template_path': os.path.join(os.path.dirname(__file__),
                                                  '../templates'),
                    'modules': ['cauth'],
                    'debug': True,
                    }
        self.auth = {'ldap':
                     {'host': 'ldap://ldap.tests.dom',
                         'dn': 'cn=%(username)s,ou=Users,dc=tests,dc=dom',
                         'sn': 'sn',
                         'mail': 'mail', },
                     'github':
                     {'top_domain': 'tests.dom',
                      'auth_url': 'https://github.com/login/oauth/authorize',
                      'redirect_uri':
                      'http://tests.dom/auth/login/github/callback"',
                      'client_id': 'XXX',
                      'client_secret': 'YYY', },
                     'users':
                     {"user1":
                      {"lastname": "Demo user1",
                       "mail": "user1@tests.dom",
                       "password": crypt.crypt("userpass",
                                               "$6$EFeaxATWohJ")}},
                     'localdb':
                     {"managesf_url": "http://tests.dom", }, }
        self.sqlalchemy = {'url': 'sqlite:///%s' % tempfile.mkstemp()[1],
                           'echo': False,
                           'encoding': 'utf-8',
                           }
        self.services = ['redmine', 'gerrit']
        self.logging = {'loggers':
                        {'root': {'level': 'INFO', 'handlers': ['console']},
                         'cauth': {'level': 'DEBUG', 'handlers': ['console']},
                         'py.warnings': {'handlers': ['console']},
                         '__force_dict__': True},
                        'handlers': {
                            'console': {'level': 'DEBUG',
                                        'class': 'logging.StreamHandler',
                                        'formatter': 'simple'}},
                        'formatters': {
                            'simple': {
                                'format': (
                                    '%(asctime)s %(levelname)-5.5s [%(name)s]'
                                    '[%(threadName)s] %(message)s')}
                            }
                        }

    def __getitem__(self, key):
        return getattr(self, key, None)
