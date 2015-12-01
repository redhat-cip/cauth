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

import json
from unittest import TestCase

from contextlib import nested
from mock import patch, Mock
from stevedore import driver

from cauth.tests.common import dummy_conf, FakeResponse


class TestGerritPlugin(TestCase):
    @classmethod
    def setupClass(cls):
        cls.conf = dummy_conf()

    @classmethod
    def tearDownClass(cls):
        pass

    def gerrit_add_sshkeys_mock(self, *args, **kwargs):
        self.assertIn('data', kwargs)
        self.assertIn('auth', kwargs)
        self.key_amount_added += 1
        return FakeResponse(200)

    def gerrit_get_account_id_mock(self, *args, **kwargs):
        data = json.dumps({'_account_id': 42})
        # Simulate the garbage that occurs in live tests
        data = 'garb' + data
        return FakeResponse(200, data)

    def gerrit_get_account_id_mock2(self, *args, **kwargs):
        data = json.dumps({'_account_id': 0})
        # Simulate the garbage that occurs in live tests
        data = 'garb' + data
        return FakeResponse(200, data)

    def test_gerrit_install_ssh_keys(self):
        ger = driver.DriverManager(
            namespace='cauth.service',
            name='gerrit',
            invoke_on_load=True,
            invoke_args=(self.conf,)).driver
        self.key_amount_added = 0
        keys = [{'key': 'k1'}, {'key': 'k2'}]
        with patch('cauth.service.gerrit.requests') as r:
            r.post = self.gerrit_add_sshkeys_mock
            ger.add_sshkeys('john', keys)
        self.assertEqual(self.key_amount_added, len(keys))

    def test_gerrit_add_in_acc_external(self):
        class FakeDB():
            def __init__(self, success=True):
                self.success = success

            def cursor(self):
                return FakeCursor(self.success)

            def commit(self):
                pass

        class FakeCursor():
            def __init__(self, success):
                self.success = success

            def execute(self, sql):
                if not self.success:
                    raise Exception

        ger = driver.DriverManager(
            namespace='cauth.service',
            name='gerrit',
            invoke_on_load=True,
            invoke_args=(self.conf,)).driver
        with patch('cauth.service.gerrit.MySQLdb') as m:
            m.connect = lambda *args, **kwargs: FakeDB()
            ret = ger.add_account_as_external(42, 'john')
        self.assertEqual(True, ret)
        with patch('cauth.service.gerrit.MySQLdb') as m:
            m.connect = lambda *args, **kwargs: FakeDB(False)
            ret = ger.add_account_as_external(42, 'john')
        self.assertEqual(False, ret)

    def test_create_gerrit_user(self):
        ger = driver.DriverManager(
            namespace='cauth.service',
            name='gerrit',
            invoke_on_load=True,
            invoke_args=(self.conf,)).driver
        with patch('cauth.service.gerrit.requests') as r:
            r.put = lambda *args, **kwargs: FakeResponse(200)
            r.get = self.gerrit_get_account_id_mock
            ger.add_account_as_external = Mock()
            ger.register_new_user({'login': 'john',
                                   'email': 'john@tests.dom',
                                   'name': 'John Doe',
                                   'ssh_keys': []})
            self.assertEqual(True, ger.add_account_as_external.called)
        with patch('cauth.service.gerrit.requests') as r:
            r.put = lambda *args, **kwargs: FakeResponse(200)
            r.get = self.gerrit_get_account_id_mock2
            ger.add_account_as_external = Mock()
            ger.register_new_user({'login': 'john',
                                   'email': 'john@tests.dom',
                                   'name': 'John Doe',
                                   'ssh_keys': []})
            self.assertEqual(False, ger.add_account_as_external.called)

    def test_create_managesf_user(self):
        msf = driver.DriverManager(
            namespace='cauth.service',
            name='managesf',
            invoke_on_load=True,
            invoke_args=(self.conf,)).driver
        patches = [patch('cauth.service.managesf.requests.post'),
                   patch('cauth.service.managesf.create_ticket'),
                   patch('cauth.service.managesf.orig_conf'), ]
        with nested(*patches) as (post, create_ticket, p_conf):
            p_conf.app = self.conf.app
            create_ticket.return_value = 'MAGICCOOKIE'
            msf.register_new_user({'login': 'john',
                                   'email': 'john@tests.dom',
                                   'name': 'John Doe',
                                   'ssh_keys': []})
            url = "%s/manage/services_users/" % self.conf.managesf['url']
            data = json.dumps({"full_name": "John Doe",
                               "email": "john@tests.dom",
                               "username": "john",
                               "ssh_keys": []},
                              default=lambda o: o.__dict__)
            headers = {"Content-type": "application/json"}
            cookie = {'auth_pubtkt': 'MAGICCOOKIE'}
            post.assert_called_with(url,
                                    data=data,
                                    headers=headers,
                                    cookies=cookie)
