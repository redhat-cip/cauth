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


import json
import logging
import time
import urllib

from pecan import conf as orig_conf
import requests

from cauth.service import base
from cauth.utils.common import create_ticket


logger = logging.getLogger(__name__)


class ManageSFServicePlugin(base.BaseServicePlugin):
    """This plugin deals with the ManageSF wrapper."""

    _config_section = "managesf"

    def register_new_user(self, user):
        _user = {"full_name": user['name'],
                 "email": str(user['email']),
                 "username": user['login'],
                 "ssh_keys": user.get('ssh_keys', []),
                 "external_id": user['external_id']
                 }
        data = json.dumps(_user, default=lambda o: o.__dict__)

        headers = {"Content-type": "application/json"}
        url = "%s/manage/services_users/" % self.conf['url']
        # assuming the admin user is called admin
        validity = time.time() + orig_conf.app['cookie_period']
        ticket = create_ticket(uid='admin',
                               validuntil=validity)
        cookie = {'auth_pubtkt': urllib.quote_plus(ticket)}
        logger.debug('user declaration to managesf: %s' % data)
        resp = requests.post(url, data=data, headers=headers,
                             cookies=cookie)
        logger.debug('managesf responded with code: %s' % resp.status_code)
