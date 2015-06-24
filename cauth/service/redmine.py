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

import logging

from pysflib.sfredmine import RedmineUtils

from cauth.service import base


logger = logging.getLogger(__name__)


class RedmineServicePlugin(base.BaseServicePlugin):
    """This plugin deals with the redmine bug tracker service."""

    _config_section = "redmine"

    def register_new_user(self, user):
        r = RedmineUtils(self.conf['apiurl'],
                         key=self.conf['apikey'])
        try:
            r.create_user(user['login'],
                          user['email'],
                          user['name'])
        except Exception as e:
            raise base.UserRegistrationError(e.message)
