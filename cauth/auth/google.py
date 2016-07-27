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

from cauth.auth import base, oauth2


"""Google OAuth2 API authentication plugin."""


logger = logging.getLogger(__name__)


class GoogleAuthPlugin(oauth2.BaseOAuth2Plugin):
    """Allows a google user to authenticate with the OAuth protocol.
    """

    provider = "Google"

    _config_section = "google"
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    scope = 'email profile'
    access_token_url = 'https://www.googleapis.com/oauth2/v4/token'

    def get_error(self, **auth_context):
        """Parse the auth context returned by OAuth's first step."""
        error = auth_context.get('error', None)
        error_description = auth_context.get('error_description', None)
        return error, error_description

    def get_provider_id(self, user_data):
        """Return a provider-specific unique id from the user data."""
        return user_data.get('id') or user_data.get('nickname')

    def get_user_data(self, token):

        user_url = ("https://www.googleapis.com"
                    "/plus/v1/people/me?access_token=%s")
        resp = requests.get(user_url % token)
        if not resp.ok:
            logger.error(user_url % '<REDACTED>')
            if resp.json():
                data = resp.json()
                error = data.get("error", {}).get("message", "Unknown error")
            else:
                error = repr(resp)
            raise base.UnauthenticatedError(error)
        data = resp.json()
        name = (data.get('name', {}).get('givenName', '') + ' ' +
                data.get('name', {}).get('familyName', '')).strip()

        # no ssh keys stored on a google profile
        ssh_keys = []

        emails = data.get('emails')
        # this is a wild guess, can people have many account emails ?
        for mail in emails:
            if mail.get('type') == "account":
                email = mail.get('value')
                break
        # use mail's local part to ensure probable unicity
        # (nickname might not be unique)
        login = email.split('@')[0]
        if not name:
            name = login
        logger.info(
            'Client %s (%s) authenticated through Google API'
            % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': self.get_provider_id(data)}}
