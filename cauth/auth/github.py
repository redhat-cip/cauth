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

from cauth.auth import base, oauth2


"""GitHub-based authentication plugins."""


logger = logging.getLogger(__name__)


class BaseGithubAuthPlugin(base.AuthProtocolPlugin):

    _config_section = "github"
    auth_url = 'https://github.com/login/oauth/authorize'

    def organization_allowed(self, token):
        allowed_orgs = self.conf.get('allowed_organizations')
        if allowed_orgs:
            resp = self.get_user_orgs(token)
            user_orgs = resp.json()
            user_orgs = [org['login'] for org in user_orgs]

            allowed_orgs = allowed_orgs.split(',')
            allowed_orgs = filter(None, allowed_orgs)
            allowed = set(user_orgs) & set(allowed_orgs)
            if not allowed:
                return False
        return True

    def get_domain(self):
        return self.auth_url


class GithubPersonalAccessTokenAuthPlugin(BaseGithubAuthPlugin):
    """Allows a github user to authenticate with a personal access token,
    see https://github.com/blog/1509-personal-api-tokens and make sure the
    token has at least the following rights:
    'user:email, read:public_key, read:org'
    """

    def get_user_orgs(self, token):
        basic_auth = requests.auth.HTTPBasicAuth(token,
                                                 'x-oauth-basic')
        resp = requests.get("https://api.github.com/user/orgs",
                            auth=basic_auth)
        if not resp.ok:
            msg = 'Failed to get organizations'
            logger.error(msg, resp)
        return resp

    @classmethod
    def get_args(cls):
        return {"token": {"description": "the user's personal API token"}}

    def authenticate(self, **auth_context):
        token = auth_context.get('token', None)
        basic_auth = requests.auth.HTTPBasicAuth(token,
                                                 'x-oauth-basic')
        try:
            resp = requests.get("https://api.github.com/user",
                                auth=basic_auth)
            if not resp.ok:
                msg = 'Failed to authenticate user'
                logger.error(msg, resp)
            data = resp.json()

            resp = requests.get("https://api.github.com/user/keys",
                                auth=basic_auth)
            if not resp.ok:
                msg = 'Failed to get keys'
                logger.error(msg, resp)

            ssh_keys = resp.json()
        except Exception as e:
            logger.error(e.message)
            raise base.UnauthenticatedError(e.message)

        login = data.get('login')
        email = data.get('email')
        name = data.get('name')

        if not self.organization_allowed(token):
            raise base.UnauthenticatedError("Organization not allowed")
        msg = 'Client %s (%s) authenticated with Github Personal Access token'
        logger.info(msg % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': data.get('id') or login}}


class GithubAuthPlugin(BaseGithubAuthPlugin,
                       oauth2.BaseOAuth2Plugin):
    """Allows a Github user to authenticate with the OAuth protocol.
    """

    provider = "Github"

    scope = 'user:email, read:public_key, read:org'
    access_token_url = 'https://github.com/login/oauth/access_token'

    def get_user_orgs(self, token):
        headers = {'Authorization': self.access_token_type + ' ' + token}
        resp = requests.get("https://api.github.com/user/orgs",
                            headers=headers)
        if not resp.ok:
            logger.error('Failed to get keys', resp)
        return resp

    def get_error(self, **auth_context):
        """Parse the auth context returned by OAuth's first step."""
        error = auth_context.get('error', None)
        error_description = auth_context.get('error_description', None)
        return error, error_description

    def get_provider_id(self, user_data):
        """Return a provider-specific unique id from the user data."""
        return user_data.get('id') or user_data.get('login')

    def get_user_data(self, token):

        headers = {'Authorization': self.access_token_type + ' ' + token}
        resp = requests.get("https://api.github.com/user",
                            headers=headers)
        if not resp.ok:
            logger.error('Failed to authenticate', resp)
            raise base.UnauthenticatedError(resp)
        data = resp.json()
        login = data.get('login')
        name = data.get('name')

        resp = requests.get("https://api.github.com/users/%s/keys" % login,
                            headers=headers)
        if not resp.ok:
            logger.error('Failed to get keys', resp)
            raise base.UnauthenticatedError(resp)
        ssh_keys = resp.json()

        if not self.organization_allowed(token):
            raise base.UnauthenticatedError("Organization not allowed")

        resp = requests.get("https://api.github.com/user/emails",
                            headers=headers)
        if not resp.ok:
            logger.error('Failed to get emails', resp)
            raise base.UnauthenticatedError(resp)
        emails = resp.json()

        logger.debug("Email received from apigh/user/emails: %s" % str(emails))
        # Get email from autorize response, just in case no primary is set
        email = data.get('email')
        for mail in emails:
            if mail.get('primary') is True:
                email = mail.get('email')
                break

        logger.info(
            'Client %s (%s) authenticated through Github'
            % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys,
                'external_auth': {'domain': self.get_domain(),
                                  'external_id': self.get_provider_id(data)}}
