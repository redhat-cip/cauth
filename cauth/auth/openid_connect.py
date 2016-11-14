#!/usr/bin/env python
#
# Copyright (C) 2016 Red Hat
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
from pecan import request
from oic.oic import Client
from oic.oic.message import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from cauth.auth import base
from cauth.model import db

"""OpenID Connect authentication plugin."""


logger = logging.getLogger(__name__)


class OpenIDConnectAuthPlugin(base.AuthProtocolPlugin):

    _config_section = "openid_connect"

    provider_config = None

    @classmethod
    def get_args(cls):
        return {}

    def get_domain(self):
        return self.conf['issuer_url']

    def _get_client(self):
        client = Client(client_id=self.conf['client_id'],
                        client_authn_method=CLIENT_AUTHN_METHOD)
        # Set client configurations based on issuer_url
        if not OpenIDConnectAuthPlugin.provider_config:
            OpenIDConnectAuthPlugin.provider_config = client.provider_config(
                self.conf['issuer_url'])
        else:
            client.handle_provider_config(
                OpenIDConnectAuthPlugin.provider_config,
                self.conf['issuer_url'])
        return client

    def _redirect(self, back, response):
        """Send the user to the OpenID Connect auth page"""
        client = self._get_client()
        response.status_code = 302
        response.location = client.construct_AuthorizationRequest(
            request_args={
                "response_type": ["code"],
                "response_mode": "query",
                "state": db.put_url(back, "openid_connect"),
                "redirect_uri": self.conf["redirect_uri"],
                "scope": ["openid", "profile"],
                "client_id": self.conf["client_id"],
            }).request(client.authorization_endpoint)
        logger.debug("Redirecting to %s" % response.location)

    def _authenticate(self, state, code, query_string):
        """Validate callback code and retrieve user info"""
        if not code:
            raise base.UnauthenticatedError('Invalid OAuth code')

        # Check query_string
        client = self._get_client()
        try:
            client.parse_response(AuthorizationResponse,
                                  info=query_string,
                                  sformat="urlencoded")
        except Exception as e:
            logger.error("Couldn't parse callback response (%s)" % repr(e))
            logger.debug("QueryString error '%s'" % query_string)
            raise base.UnauthenticatedError('Invalid callback query string')

        # Request token
        try:
            token = client.do_access_token_request(
                scope="openid",
                state=state,
                authn_method="client_secret_post",
                request_args={
                    "code": code,
                    "redirect_uri": self.conf["redirect_uri"],
                    "client_id": self.conf["client_id"],
                    "client_secret": self.conf["client_secret"],
                }
            )
        except Exception as e:
            logger.error("Couldn't obtain user token (%s)" % repr(e))
            raise base.UnauthenticatedError('Couldn\'t fetch user-info')

        user_info = token.to_dict().get("id_token")
        if not isinstance(user_info, dict):
            user_info = {}

        email = user_info.get('email')
        name = user_info.get('name')
        uid = user_info.get('sub')
        if not email or '@' not in email or not name or not uid:
            logger.error("Invalid user token")
            logger.debug("User token error '%s'" % user_info)
            raise base.UnauthenticatedError('Couldn\'t decode token')

        # All the user info we need are in the token, no need to request more
        # info = client.do_user_info_request(token = token["access_token"])

        return {
            'login': email.split('@')[0],
            'email': email,
            'name': name,
            'ssh_keys': [],
            'external_auth': {'domain': self.get_domain(),
                              'external_id': uid}}

    def authenticate(self, **context):
        if context.get('calling_back', False):
            return self._authenticate(
                context["state"],
                context.get("code"),
                request.query_string)
        else:
            self._redirect(context['back'], context['response'])
