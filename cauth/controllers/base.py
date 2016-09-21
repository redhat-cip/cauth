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

from pecan import expose, response, request, conf, abort, render
from pecan.rest import RestController
from stevedore import driver

from cauth.auth import base
from cauth.utils import common


logger = logging.getLogger(__name__)


class BaseLoginController(RestController):

    def make_auth_info(self, kwargs):
        """Build the new auth info structure from args posted with a form"""
        auth_info = {}
        auth_info['back'] = kwargs.get('back', None)
        auth_info['method'] = kwargs.get('method', 'Password')
        auth_info['args'] = {}
        try:
            _args = driver.DriverManager(
                namespace='cauth.authentication',
                name=auth_info['method'],
                invoke_on_load=False).driver.get_args()
            # set args to default None value
            auth_args = dict((u, kwargs.get(u, None)) for u in _args)
            auth_info['args'] = auth_args
        except RuntimeError:
            # will be caught later on
            pass
        return auth_info

    def _json_login(self, auth_info):
        auth_context = {}
        auth_context['response'] = response
        auth_context['back'] = auth_info.get('back', None)
        if not auth_context['back']:
            logger.error('Client requests authentication without back url.')
            abort(422)
        auth_context.update(auth_info.get('args', {}))
        auth_method = auth_info.get('method', 'NO_METHOD')
        try:
            auth_plugin = driver.DriverManager(
                namespace='cauth.authentication',
                name=auth_method,
                invoke_on_load=True,
                invoke_args=(conf,)).driver
        except (RuntimeError, base.AuthProtocolNotAvailableError) as e:
            response.status = 401
            msg = '"%s" is not a valid authentication method' % auth_method
            logger.error(msg + ': %s' % e)
            response.body = render('login.html',
                                   dict(back=auth_context['back'],
                                        message=msg))
            return response.body
        try:
            logger.info('%s plugin loaded' % auth_method)
            valid_user = auth_plugin.authenticate(**auth_context)
        except base.UnauthenticatedError:
            response.status = 401
            response.body = render('login.html',
                                   dict(back=auth_context['back'],
                                        message='Authentication failed.'))
            return response.body
        if valid_user:
            logger.info('%s successfully authenticated' % valid_user['login'])
            common.setup_response(valid_user, auth_context['back'])

    @expose()
    def post(self, **kwargs):
        logger.info('Client requests authentication.')
        try:
            auth_info = request.json
            self._json_login(auth_info)
        except ValueError:
            # old-style values passed through a form
            auth_info = self.make_auth_info(kwargs)
            self._json_login(auth_info)

    @expose(template='login.html')
    def get(self, **kwargs):
        back = kwargs.get('back', '/auth/logout')
        logger.info('Client requests the login page.')
        auth_methods = [k for k, v in conf.get('auth', {})]
        return dict(back=back, message='', auth_methods=auth_methods)
