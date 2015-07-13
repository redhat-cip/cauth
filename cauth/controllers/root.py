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

from pecan import expose, response, conf
from pecan.rest import RestController

from cauth.auth import base as exceptions
from cauth.controllers import base, github, introspection, openid
from cauth.utils.common import LOGOUT_MSG


logger = logging.getLogger(__name__)


class LogoutController(RestController):
    @expose(template='login.html')
    def get(self, **kwargs):
        response.delete_cookie('auth_pubtkt', domain=conf.app.cookie_domain)
        return dict(back='/', message=LOGOUT_MSG)


class RootController(object):
    login = base.BaseLoginController()
    try:
        login.github = github.GithubController()
        login.githubAPIkey = github.PersonalAccessTokenGithubController()
    except exceptions.AuthProtocolNotAvailableError as e:
        logger.error("%s - skipping callback endpoint" % e.message)
    try:
        login.openid = openid.OpenIDController()
    except exceptions.AuthProtocolNotAvailableError as e:
        logger.error("%s - skipping callback endpoint" % e.message)
    about = introspection.IntrospectionController()

    logout = LogoutController()
