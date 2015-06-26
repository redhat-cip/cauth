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

from pecan import conf, expose
from pecan.rest import RestController
import pkg_resources
from stevedore import driver

from cauth.auth import base


class IntrospectionController(RestController):
    """A controller that allows a client to know more about the server."""

    def get_cauth_version(self):
        cauth = pkg_resources.get_distribution('cauth')
        return cauth.version

    def iter_auth_plugins(self):
        for plugin in pkg_resources.iter_entry_points('cauth.authentication'):
            plugin_name = plugin.name
            try:
                auth_plugin = driver.DriverManager(
                    namespace='cauth.authentication',
                    name=plugin.name,
                    invoke_on_load=True,
                    invoke_args=(conf,)).driver
                if auth_plugin:
                    yield plugin_name
            except base.AuthProtocolNotAvailableError:
                pass

    @expose(template='json')
    def index(self, **kwargs):
        auth_methods = [a for a in self.iter_auth_plugins()]
        return_value = {'service': {
            'name': 'cauth',
            'version': self.get_cauth_version(),
            'auth_methods': auth_methods, }}
        return return_value
