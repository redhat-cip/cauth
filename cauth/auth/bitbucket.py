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
from requests.utils import quote

from cauth.auth import base, oauth2


"""BitBucket OAuth2 API authentication plugin."""


logger = logging.getLogger(__name__)


class BitBucketAuthPlugin(oauth2.BaseOAuth2Plugin):
    """Allows a bitbucket user to authenticate with the OAuth protocol.
    """

    provider = "BitBucket"

    _config_section = "bitbucket"
    auth_url = 'https://bitbucket.org/site/oauth2/authorize'
    scope = 'email account'
    access_token_url = 'https://bitbucket.org/site/oauth2/access_token'

    def get_error(self, **auth_context):
        """Parse the auth context returned by OAuth's first step."""
        error = auth_context.get('error', None)
        error_description = auth_context.get('error_description', None)
        return error, error_description

    def get_provider_id(self, user_data):
        """Return a provider-specific unique id from the user data."""
        # bitbucket uuid is between brackets, we do not want that
        return user_data.get('uuid')[1:-1] or user_data.get('username')

    def get_user_data(self, token):

        user_url = ("https://api.bitbucket.org/2.0/user?access_token=%s")
        resp = requests.get(user_url % quote(token, safe=''))
        if not resp.ok:
            logger.error(user_url % '<REDACTED>')
            if resp.json():
                data = resp.json()
                error = data.get("error", {}).get("message", "Unknown error")
            else:
                error = repr(resp)
            raise base.UnauthenticatedError(error)
        data = resp.json()
        login = data.get('username')
        name = data.get('display_name')
        external_id = self.get_provider_id(data)

        email_url = ("https://api.bitbucket.org"
                     "/2.0/user/emails?access_token=%s")
        resp = requests.get(email_url % quote(token, safe=''))
        if not resp.ok:
            logger.error(email_url % '<REDACTED>')
            if resp.json():
                data = resp.json()
                error = data.get("error", {}).get("message", "Unknown error")
            else:
                error = repr(resp)
            raise base.UnauthenticatedError(error)
        data = resp.json()
        emails = data.get('values', [])
        for e_data in emails:
            if e_data.get('is_primary'):
                email = e_data['email']
                break

        ssh_url = ("https://api.bitbucket.org"
                   "/1.0/users/%s/ssh-keys?access_token=%s")
        resp = requests.get(ssh_url % (quote(login), quote(token, safe='')))
        if not resp.ok:
            logger.error(ssh_url % (quote(login), '<REDACTED>'))
            if resp.json():
                data = resp.json()
                error = data.get("error", {}).get("message", "Unknown error")
            else:
                error = repr(resp)
            raise base.UnauthenticatedError(error)
        keys = resp.json()
        ssh_keys = []
        for k in keys:
            ssh_keys.append({'key': k.get('key')})
        logger.info(
            'Client %s (%s) authenticated through BitBucket API'
            % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': external_id}}
