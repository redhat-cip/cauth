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

import base64
import hashlib
import time
import urllib

from M2Crypto import RSA
from pecan import response, conf
from cauth.utils import userdetails


LOGOUT_MSG = "You have been successfully logged " \
             "out of all the Software factory services."


def signature(data):
    rsa_priv = RSA.load_key(conf.app['priv_key_path'])
    dgst = hashlib.sha1(data).digest()
    sig = rsa_priv.sign(dgst, 'sha1')
    sig = base64.b64encode(sig)
    return sig


def create_ticket(**kwargs):
    ticket = ''
    for k in sorted(kwargs.keys()):
        if ticket is not '':
            ticket = ticket + ';'
        ticket = ticket + '%s=%s' % (k, kwargs[k])

    ticket = ticket + ";sig=%s" % signature(ticket)
    return ticket


def pre_register_user(user):
    if user.get('name', None) is None:
        user['name'] = 'User %s' % user['login']
    if user.get('email', None) is None:
        user['email'] = '%s@%s' % (user['login'], conf.app['cookie_domain'])

    udc = userdetails.UserDetailsCreator(conf)
    return udc.create_user(user)


def setup_response(user, back):
    c_id = pre_register_user(user)
    # c_id is added to the cauth cookie so that the storyboard client can
    # authenticate to storyboard_api.
    # the c_id is stored in browser local storage after authentication.
    ticket = create_ticket(uid=user['login'],
                           cid=c_id,
                           validuntil=(
                               time.time() + conf.app['cookie_period']))
    enc_ticket = urllib.quote_plus(ticket)
    response.set_cookie('auth_pubtkt',
                        value=enc_ticket,
                        domain=conf.app['cookie_domain'],
                        max_age=conf.app['cookie_period'],
                        overwrite=True)
    response.status_code = 303
    response.location = urllib.unquote_plus(back).decode("utf8")
