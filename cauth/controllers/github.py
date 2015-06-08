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

import urllib
import logging
import requests
from requests.exceptions import ConnectionError

from pecan import expose, response, conf, abort

from cauth.model import db
from cauth.utils import common


logger = logging.getLogger(__name__)


class PersonalAccessTokenGithubController(object):
    """Allows a github user to authenticate with a personal access token,
    see https://github.com/blog/1509-personal-api-tokens and make sure the
    token has at least the following rights:
    'user:email, read:public_key, read:org'"""

    def organization_allowed(self, token):
        allowed_orgs = conf.auth['github'].get('allowed_organizations')

        if allowed_orgs:
            basic_auth = requests.auth.HTTPBasicAuth(token,
                                                     'x-oauth-basic')
            resp = requests.get("https://api.github.com/user/orgs",
                                auth=basic_auth)
            user_orgs = resp.json()
            user_orgs = [org['login'] for org in user_orgs]

            allowed_orgs = allowed_orgs.split(',')
            allowed_orgs = filter(None, allowed_orgs)
            allowed = set(user_orgs) & set(allowed_orgs)
            if not allowed:
                return False
        return True

    @expose()
    def index(self, **kwargs):
        if 'back' not in kwargs:
            logger.error('Client requests authentication without back url.')
            abort(422)
        back = kwargs['back']
        if 'token' not in kwargs:
            logger.error('Client requests authentication without token.')
            abort(422)
        token = kwargs['token']
        resp = requests.get("https://api.github.com/user",
                            auth=requests.auth.HTTPBasicAuth(token,
                                                             'x-oauth-basic'))
        data = resp.json()
        login = data.get('login')
        email = data.get('email')
        name = data.get('name')
        resp = requests.get("https://api.github.com/user/keys",
                            auth=requests.auth.HTTPBasicAuth(token,
                                                             'x-oauth-basic'))
        ssh_keys = resp.json()

        if not self.organization_allowed(token):
            abort(401)
        msg = 'Client %s (%s) auth with Github Personal Access token success.'
        logger.info(msg % (login, email))
        common.setup_response(login, back, email, name, ssh_keys)


class GithubController(object):
    def get_access_token(self, code):
        github = conf.auth['github']
        url = "https://github.com/login/oauth/access_token"
        params = {
            "client_id": github['client_id'],
            "client_secret": github['client_secret'],
            "code": code,
            "redirect_uri": github['redirect_uri']}
        headers = {'Accept': 'application/json'}
        try:
            resp = requests.post(url, params=params, headers=headers)
        except ConnectionError:
            return None

        jresp = resp.json()
        if 'access_token' in jresp:
            return jresp['access_token']
        elif 'error' in jresp:
            logger.error("An error occured (%s): %s" % (
                jresp.get('error', None),
                jresp.get('error_description', None)))
        return None

    def organization_allowed(self, token):
        allowed_orgs = conf.auth['github'].get('allowed_organizations')
        if allowed_orgs:
            resp = requests.get("https://api.github.com/user/orgs",
                                headers={'Authorization': 'token ' + token})

            user_orgs = resp.json()
            user_orgs = [org['login'] for org in user_orgs]

            allowed_orgs = allowed_orgs.split(',')
            allowed_orgs = filter(None, allowed_orgs)
            allowed = set(user_orgs) & set(allowed_orgs)
            if not allowed:
                return False
        return True

    @expose()
    def callback(self, **kwargs):
        if 'error' in kwargs:
            logger.error('GITHUB callback called with an error (%s): %s' % (
                kwargs.get('error', None),
                kwargs.get('error_description', None)))
        state = kwargs.get('state', None)
        code = kwargs.get('code', None)
        if not state or not code:
            logger.error(
                'GITHUB callback called without state or code as params.')
            abort(400)

        # Verify the state previously put in the db
        back = db.get_url(state)
        if not back:
            logger.error('GITHUB callback called with an unknown state.')
            abort(401)

        token = self.get_access_token(code)
        if not token:
            logger.error('Unable to request a token on GITHUB.')
            abort(401)

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
            abort(401)

        logger.info(
            'Client (username: %s, email: %s) auth on GITHUB success.'
            % (login, email))
        common.setup_response(login, back, email, name, ssh_keys)

    @expose()
    def index(self, **kwargs):
        if 'back' not in kwargs:
            logger.error(
                'Client requests authentication via GITHUB' +
                'without back in params.')
            abort(422)
        back = kwargs['back']
        state = db.put_url(back)
        scope = 'user:email, read:public_key, read:org'
        github = conf.auth['github']
        logger.info(
            'Client requests authentication via GITHUB -' +
            'redirect to %s.' % github['redirect_uri'])
        response.status_code = 302
        response.location = github['auth_url'] + "?" + \
            urllib.urlencode({'client_id': github['client_id'],
                              'redirect_uri': github['redirect_uri'],
                              'state': state,
                              'scope': scope})
