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

from cauth.utils import common


logger = logging.getLogger(__name__)


class BaseLoginController(RestController):
    def __init__(self, *args, **kwargs):
        self.conf = conf
        self.auth_methods = []

    def register(self, auth_method):
        self.auth_methods.append(auth_method)

    def check_valid_user(self, username, password):
        for auth_method in self.auth_methods:
            authenticated = auth_method(self.conf, username, password)
            if authenticated:
                return authenticated

    @expose()
    def post(self, **kwargs):
        logger.info('Client requests authentication.')
        back = kwargs.get('back')
        if not back:
            logger.error('Client requests authentication without back url.')
            abort(422)

        username = kwargs.get('username')
        password = kwargs.get('password')
        if username and password:
            valid_user = self.check_valid_user(username, password)
            if not valid_user:
                logger.error('Client requests authentication with wrong'
                             ' credentials.')
                response.status = 401
                return render('login.html',
                              dict(back=back, message='Authorization failed.'))
            email, lastname, sshkey = valid_user
            logger.info('Client requests authentication success %s' % username)
            common.setup_response(username, back, email, lastname, sshkey)
        else:
            logger.error('Client requests authentication without credentials.')
            response.status = 401
            return render('login.html', dict(back=back,
                                             message='Authorization failed.'))

    @expose(template='login.html')
    def get(self, **kwargs):
        back = kwargs.get('back', '/auth/logout')
        logger.info('Client requests the login page.')
        return dict(back=back, message='')
