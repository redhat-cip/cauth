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
from urllib import unquote

from pecan import expose, response, abort, request
from pecan.rest import RestController

from cauth.model import db


logger = logging.getLogger(__name__)


class APIKeyController(RestController):
    # Obviously these operations can only be done once authenticated
    def guess_cauth_id(self):
        try:
            auth_pubtkt = unquote(request.cookies['auth_pubtkt'])
        except KeyError:
            return None
        infos = dict(vals.split('=', 1) for vals in auth_pubtkt.split(';'))
        return infos.get('cid')

    def check_identity(self, cauth_id):
        try:
            if self.guess_cauth_id() != cauth_id:
                abort(401, 'Wrong user')
            else:
                return True
        except Exception as e:
            abort(401, str(e))

    @expose('json')
    def get(self, **kwargs):
        cauth_id = kwargs.get('cauth_id')
        if not cauth_id:
            cauth_id = self.guess_cauth_id()
        if not cauth_id:
            abort(401, 'Authenticate first')
        self.check_identity(cauth_id)
        key = db.get_api_key_from_cauth_id(cauth_id)
        if key:
            return {'api_key': key}
        else:
            abort(404, 'User has no API key')

    @expose('json')
    def post(self, cauth_id=None):
        if not cauth_id:
            cauth_id = self.guess_cauth_id()
        self.check_identity(cauth_id)
        try:
            key = db.create_api_key(cauth_id)
            logger.debug('Created API Key for cauth_id %s' % cauth_id)
            response.status_code = 201
            return {'api_key': key}
        except db.APIKeyUnicityError:
            abort(409, 'An API key already exists for this user')

    @expose()
    def delete(self, cauth_id=None):
        if not cauth_id:
            cauth_id = self.guess_cauth_id()
        self.check_identity(cauth_id)
        db.delete_api_key(cauth_id)
        logger.debug('Deleted API Key for cauth_id %s' % cauth_id)
        response.status_code = 204
