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
from requests.exceptions import ConnectionError
import urllib

from cauth.auth import base
from cauth.model import db


"""GitHub-based authentication plugins."""


logger = logging.getLogger(__name__)


class BaseGithubAuthPlugin(base.AuthProtocolPlugin):

    _config_section = "github"

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
        return resp

    def authenticate(self, **auth_context):
        token = auth_context.get('token', None)
        try:
            basic_auth = requests.auth.HTTPBasicAuth(token,
                                                     'x-oauth-basic')
            resp = requests.get("https://api.github.com/user",
                                auth=basic_auth)
            data = resp.json()
        except Exception as e:
            raise base.UnauthenticatedError(e.message)
        login = data.get('login')
        email = data.get('email')
        name = data.get('name')
        resp = requests.get("https://api.github.com/user/keys",
                            auth=basic_auth)
        ssh_keys = resp.json()

        if not self.organization_allowed(token):
            raise base.UnauthenticatedError("Organization not allowed")
        msg = 'Client %s (%s) authenticated with Github Personal Access token'
        logger.info(msg % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys}


class GithubAuthPlugin(BaseGithubAuthPlugin):
    """Allows a Github user to authenticate with the oAuth protocol.
    """

    def get_user_orgs(self, token):
        resp = requests.get("https://api.github.com/user/orgs",
                            headers={'Authorization': 'token ' + token})
        return resp

    def authenticate(self, **auth_context):
        if auth_context.get('calling_back', False):
            state = auth_context.get('state', None)
            code = auth_context.get('code', None)
            error = auth_context.get('error', None)
            error_description = auth_context.get('error_description', None)
            return self._authenticate(state, code, error, error_description)
        else:
            back = auth_context['back']
            response = auth_context['response']
            self.redirect(back, response)

    def redirect(self, back, response):
        """Send the user to the Github auth page"""
        state = db.put_url(back)
        scope = 'user:email, read:public_key, read:org'
        response.status_code = 302
        response.location = self.conf['auth_url'] + "?" + \
            urllib.urlencode({'client_id': self.conf['client_id'],
                              'redirect_uri': self.conf['redirect_uri'],
                              'state': state,
                              'scope': scope})

    def _authenticate(self, state=None, code=None,
                      error=None, error_description=None):
        """Called at the callback level"""
        if error:
            err = 'GITHUB callback called with an error (%s): %s' % (
                error,
                error_description)
            raise base.UnauthenticatedError(err)
        if not state or not code:
            err = 'GITHUB callback called without state or code as params.'
            raise base.UnauthenticatedError(err)

        token = self.get_access_token(code)
        if not token:
            err = 'Unable to request a token on GITHUB.'
            raise base.UnauthenticatedError(err)

        resp = requests.get("https://api.github.com/user",
                            headers={'Authorization': 'token ' + token})
        data = resp.json()
        login = data.get('login')
        email = data.get('email')
        name = data.get('name')

        resp = requests.get("https://api.github.com/users/%s/keys" % login,
                            headers={'Authorization': 'token ' + token})
        ssh_keys = resp.json()

        if not self.organization_allowed(token):
            raise base.UnauthenticatedError("Organization not allowed")

        logger.info(
            'Client %s (%s) authenticated through Github'
            % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys}

    def get_access_token(self, code):
        url = "https://github.com/login/oauth/access_token"
        params = {
            "client_id": self.conf['client_id'],
            "client_secret": self.conf['client_secret'],
            "code": code,
            "redirect_uri": self.conf['redirect_uri']}
        headers = {'Accept': 'application/json'}
        try:
            resp = requests.post(url, params=params, headers=headers)
        except ConnectionError:
            return None

        jresp = resp.json()
        if 'access_token' in jresp:
            return jresp['access_token']
        elif 'error' in jresp:
            err = "An error occured (%s): %s" % (jresp.get('error', None),
                                                 jresp.get('error_description',
                                                           None))
            raise base.UnauthenticatedError(err)
        return None
