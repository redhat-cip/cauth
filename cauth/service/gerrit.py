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

import MySQLdb
import requests

from cauth.service import base


logger = logging.getLogger(__name__)


class GerritServicePlugin(base.BaseServicePlugin):
    """This plugin deals with the Gerrit code review service."""

    _config_section = "gerrit"

    def add_sshkeys(self, username, keys):
        """add keys for username."""
        url = "%s/api/a/accounts/%s/sshkeys" % (self.conf['url'],
                                                username)
        for key in keys:
            logger.debug("Adding key %s for user %s" % (key.get('key'),
                                                        username))
            response = requests.post(url, data=key.get('key'),
                                     auth=(self.conf['admin_user'],
                                           self.conf['admin_password']))

            if not response.ok:
                msg = 'Failed to add ssh key %s of user %s' % (key.get('key'),
                                                               username)
                logger.error(msg, response)

    def add_account_as_external(self, account_id, username):
        # TODO(mhu) there's got to be a cleaner way. pygerrit ?
        db = MySQLdb.connect(passwd=self.conf['db_password'],
                             db=self.conf['db_name'],
                             host=self.conf['db_host'],
                             user=self.conf['db_user'])
        c = db.cursor()
        sql = ("INSERT IGNORE INTO account_external_ids VALUES"
               "(%d, NULL, NULL, 'gerrit:%s');" %
               (account_id, username))
        try:
            c.execute(sql)
            db.commit()
            return True
        except Exception as e:
            msg = "Could not insert user %s in account_external_ids: %s"
            logger.error(msg % (username, e.message))
            return False

    def register_new_user(self, user):
        _user = {"name": unicode(user['name']), "email": str(user['email'])}
        data = json.dumps(_user, default=lambda o: o.__dict__)

        headers = {"Content-type": "application/json"}
        url = "%s/api/a/accounts/%s" % (self.conf['url'], user['login'])
        response = requests.put(url, data=data, headers=headers,
                                auth=(self.conf['admin_user'],
                                      self.conf['admin_password']))
        if not response.ok:
            msg = 'Failed to register new user %s' % user['email']
            logger.error(msg, response)
            return False

        response = requests.get(url, headers=headers,
                                auth=(self.conf['admin_user'],
                                      self.conf['admin_password']))
        data = response.content[4:]  # there is some garbage at the beginning
        try:
            account_id = json.loads(data)['_account_id']
        except (KeyError, ValueError) as err:
            msg = 'Failed to retreive account %s from server' % user['email']
            logger.error(msg, err)
            return False

        fetch_ssh_keys = False
        if account_id:
            fetch_ssh_keys = self.add_account_as_external(account_id,
                                                          user['login'])
        if user.get('ssh_keys', None) and fetch_ssh_keys:
            self.add_sshkeys(user['login'], user['ssh_keys'])
