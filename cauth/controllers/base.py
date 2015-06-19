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

import logging

from pecan import expose, response, conf, abort, render
from pecan.rest import RestController
from stevedore import driver

from cauth.auth import base
from cauth.utils import common


logger = logging.getLogger(__name__)


class BaseLoginController(RestController):

    @expose()
    def post(self, **kwargs):
        logger.info('Client requests authentication.')
        back = kwargs.get('back')
        if not back:
            logger.error('Client requests authentication without back url.')
            abort(422)

        auth_context = kwargs
        auth_context['response'] = response

        # TODO(mhu) later, this shall be chosen automatically
        auth_plugin = driver.DriverManager(
            namespace='cauth.authentication',
            name='Password',
            invoke_on_load=True,
            invoke_args=(conf,)).driver

        try:
            valid_user = auth_plugin.authenticate(**auth_context)
        except base.UnauthenticatedError:
            response.status = 401
            return render('login.html',
                          dict(back=back, message='Authorization failed.'))
        if valid_user:
            logger.info('%s successfully authenticated' % valid_user['login'])
            common.setup_response(valid_user['login'],
                                  back,
                                  valid_user['email'],
                                  valid_user['name'],
                                  valid_user['ssh_keys'])

    @expose(template='login.html')
    def get(self, **kwargs):
        back = kwargs.get('back', '/auth/logout')
        logger.info('Client requests the login page.')
        return dict(back=back, message='')
