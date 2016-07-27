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
import requests
from requests.exceptions import ConnectionError
import urllib

from cauth.auth import base
from cauth.model import db


"""OAuth2 generic authentication plugin."""


logger = logging.getLogger(__name__)


class BaseOAuth2Plugin(base.AuthProtocolPlugin):

    # The name of the plugin goes there
    provider = "GenericOAuth2DontUseMe"
    _config_section = "OAuth2"
    # config will have the following elements:
    # * client_id: the provider's app id to use to initiate the workflow
    # * client_secret: the secret associated to client_id
    # * redirect_uri: where to get back after the provider has authenticated

    # the following fields are specific to providers and set within the
    # plugins:
    # * auth_url: where to initiate the workflow
    # * access_token_url: where to get the bearer token
    # * scope: the authorizations required, usually enough to access the user
    #   profile
    # * access_token_type: the type to declare when authenticating. Usually
    #   either 'token' or 'Bearer'

    scope = ''
    auth_url = ''
    access_token_url = ''
    access_token_type = 'token'

    @classmethod
    def get_args(cls):
        # not relevant here
        return {}

    def get_domain(self):
        return self.auth_url

    def get_error(self, **auth_context):
        """Parse the auth context returned by OAuth's first step."""
        error = None
        error_description = None
        return error, error_description

    def get_provider_id(self, user_data):
        """Return a provider-specific unique id from the user data."""
        raise NotImplementedError

    def get_user_data(self, token):
        """Query the provider to get information about the user."""
        # The return value will be something like this:
        # {'login': login,
        #  'email': email,
        #  'name': name,
        #  'ssh_keys': [{'key': 'aaabbb...'}, {'key': 'zzzyy...'}, ]
        #  'external_auth': {'domain': self.get_domain(),
        #                    'external_id': self.get_provider_id(data)}}
        raise NotImplementedError

    def authenticate(self, **auth_context):
        if auth_context.get('calling_back', False):
            state = auth_context.get('state', None)
            code = auth_context.get('code', None)
            error, error_description = self.get_error(**auth_context)
            return self._authenticate(state, code, error, error_description)
        else:
            back = auth_context['back']
            response = auth_context['response']
            self.redirect(back, response)

    def redirect(self, back, response):
        """Send the user to the provider's auth page"""
        state = db.put_url(back, self.provider)
        scope = self.scope
        response.status_code = 302
        location = self.auth_url + "?" + \
            urllib.urlencode({'client_id': self.conf['client_id'],
                              'redirect_uri': self.conf['redirect_uri'],
                              'state': state,
                              'scope': scope,
                              'response_type': 'code'})
        logger.debug('Redirecting for OAuth2 authentication (step 1) to ' +
                     location)
        response.location = location

    def _authenticate(self, state=None, code=None,
                      error=None, error_description=None):
        """Called at the callback level"""
        if error:
            err = 'OAuth callback called with an error (%s): %s' % (
                error,
                error_description)
            logger.debug(err)
            raise base.UnauthenticatedError(err)
        if not state or not code:
            err = 'OAuth callback called without state or code as params.'
            logger.debug(err)
            raise base.UnauthenticatedError(err)

        token = self.get_access_token(code)
        if not token:
            err = 'Unable to request an access token from the OAuth provider.'
            logger.debug(err)
            raise base.UnauthenticatedError(err)
        return self.get_user_data(token)

    def get_access_token(self, code):
        params = {
            "client_id": self.conf['client_id'],
            "client_secret": self.conf['client_secret'],
            "code": code,
            "redirect_uri": self.conf['redirect_uri'],
            "grant_type": "authorization_code", }
        headers = {'Accept': 'application/json'}
        logger.debug('Fetching access token at %s' % self.access_token_url)
        try:
            resp = requests.post(self.access_token_url,
                                 params=params,
                                 headers=headers)
            if not resp.ok:
                err = ('Failed to fetch access tokens at %s with the '
                       'following arguments: %s')
                params.update({'client_secret': '<REDACTED>'})
                logger.error(err % (self.access_token_url,
                                    repr(params)))
                raise base.UnauthenticatedError(resp)
        except ConnectionError as err:
            raise base.UnauthenticatedError(err)

        jresp = resp.json()
        if 'token_type' in jresp:
            logger.debug('Setting access token '
                         'type to %s' % jresp['token_type'])
            self.access_token_type = jresp['token_type']
        if 'access_token' in jresp:
            return jresp['access_token']
        elif 'error' in jresp:
            err = "An error occured (%s): %s" % (jresp.get('error', None),
                                                 jresp.get('error_description',
                                                           None))
            logger.error(err)
            raise base.UnauthenticatedError(err)
        msg = 'Access token not found - provider responded with: %s'
        logger.debug(msg % repr(jresp))
        return None
