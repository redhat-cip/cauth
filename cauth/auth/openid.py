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
import requests
from pecan import request
import urllib

from cauth.auth import base


"""OpenID authentication plugins."""


logger = logging.getLogger(__name__)


class OpenIDAuthPlugin(base.AuthProtocolPlugin):

    _config_section = "openid"

    @classmethod
    def get_args(cls):
        return {}

    def authenticate(self, **auth_context):
        if auth_context.get('calling_back', False):
            return self._authenticate(**auth_context)
        else:
            back = auth_context['back']
            response = auth_context['response']
            self.redirect(back, response)

    def redirect(self, back, response):
        """Send the user to the OpenID auth page"""
        params = {'back': back}
        response.status_code = 302
        return_to = request.host_url + self.conf['redirect_uri']
        return_to += "?" + urllib.urlencode(params)
        openid_params = {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "checkid_setup",

            "openid.claimed_id": "http://specs.openid.net/auth/2.0/"
                                 "identifier_select",
            "openid.identity": "http://specs.openid.net/auth/2.0/"
                               "identifier_select",

            "openid.realm": request.host_url,
            "openid.return_to": return_to,

            "openid.ns.sreg": "http://openid.net/sreg/1.0",
            "openid.sreg.required": "nickname,fullname,email",

            "openid.ns.ext2": "http://openid.net/srv/ax/1.0",
            "openid.ext2.mode": "fetch_request",
            "openid.ext2.type.FirstName": "http://schema.openid.net/"
                                          "namePerson/first",
            "openid.ext2.type.LastName": "http://schema.openid.net/"
                                         "namePerson/last",
            "openid.ext2.type.Email": "http://schema.openid.net/contact/email",
            "openid.ext2.type.Alias": "http://schema.openid.net/"
                                      "namePerson/friendly",
            "openid.ext2.required": "Alias,FirstName,LastName,Email"
        }

        response.location = self.conf['auth_url'] + "?" + \
            urllib.urlencode(openid_params)

    def verify_data(self, auth_context):
        logger.debug('Verifying OpenID auth data %r' % auth_context)
        verify_params = auth_context.copy()
        verify_params["openid.mode"] = "check_authentication"
        verify_response = requests.post(self.conf['auth_url'],
                                        data=verify_params)
        verify_data_tokens = verify_response.content.split()
        verify_dict = dict((token.split(":")[0], token.split(":")[1])
                           for token in verify_data_tokens)
        if (verify_response.status_code < 399
           and verify_dict.get('is_valid') == 'true'):
            # Check we have access to the required info
            for i in ['openid.sreg.nickname',
                      'openid.sreg.email',
                      'openid.sreg.fullname', ]:
                if i not in verify_params or not verify_params[i]:
                    msg = 'User must share %s' % i.split('.')[-1]
                    raise base.UnauthenticatedError(msg)
            logger.debug('OpenID auth data verified')
        else:
            msg = 'Invalid user data according to %s' % self.conf['auth_url']
            raise base.UnauthenticatedError(msg)

    def _authenticate(self, **auth_context):
        """Called at the callback level"""
        self.verify_data(auth_context)
        ssh_keys = []
        login = auth_context['openid.sreg.nickname']
        email = auth_context['openid.sreg.email']
        name = auth_context['openid.sreg.fullname']
        logger.info(
            'Client %s (%s) authenticated through OpenID'
            % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys}
