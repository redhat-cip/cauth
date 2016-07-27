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

import string
import random

from sqlalchemy import Column, Integer, String
from sqlalchemy import ForeignKey

from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.exc import NoResultFound


Base = declarative_base()
Session = scoped_session(sessionmaker())


STATE_LEN = 16
API_KEY_LEN = 32
MAX_URL_LEN = 4096


def gen_state(len):
    lst = [random.choice(string.ascii_letters + string.digits)
           for n in xrange(len)]
    return "".join(lst)


class state_mapping(Base):
    __tablename__ = 'state_mapping'

    index = Column(Integer, primary_key=True)
    state = Column(String(STATE_LEN))
    url = Column(String(MAX_URL_LEN))
    # providers are auth plugin names, PEP8 implies they must be < 80 chars
    provider = Column(String(80))


def put_url(url, provider):
    state = gen_state(STATE_LEN)
    cm = state_mapping(state=state, url=url, provider=provider)
    Session.add(cm)
    Session.commit()

    return state


def get_url(state):
    ci = Session.query(state_mapping).filter_by(state=state)
    ret = (None, None) if ci.first() is None else (ci.first().url,
                                                   ci.first().provider)
    if ci:
        ci.delete()

    return ret


def reset():
    Session.query(state_mapping).delete()


class auth_mapping(Base):
    __tablename__ = 'auth_mapping'

    cauth_id = Column(Integer, primary_key=True)
    # The IDP auth endpoint should be unique
    domain = Column(String(MAX_URL_LEN))
    # we cannot be sure every IdP will provide a numeric uid so go with String
    # and just to be sure, a huge one
    external_id = Column(String(MAX_URL_LEN))


def get_or_create_authenticated_user(domain, external_id):
    filtering = {}
    if domain:
        filtering['domain'] = domain
    if external_id:
        filtering['external_id'] = external_id
    try:
        user = Session.query(auth_mapping).filter_by(**filtering).one()
        return user.cauth_id
    except NoResultFound:
        user = auth_mapping(domain=domain,
                            external_id=external_id)
        Session.add(user)
        Session.commit()
        return user.cauth_id


def get_authenticated_user_by_cauth_id(cauth_id):
    try:
        user = Session.query(auth_mapping).filter_by(cauth_id=cauth_id).one()
        return {'cauth_id': user.cauth_id,
                'domain': user.domain,
                'external_id': user.external_id}
    except NoResultFound:
        return None


def delete_authenticated_user(cauth_id):
    # Just here for completion as relogging will simply recreate the user
    try:
        user = Session.query(auth_mapping).filter_by(cauth_id=cauth_id)
        user.delete()
    except NoResultFound:
        # do nothing
        return


class api_keys(Base):
    __tablename__ = 'api_keys'

    cauth_id = Column(Integer, ForeignKey('auth_mapping.cauth_id'),
                      primary_key=True)
    # random hash
    key = Column(String(API_KEY_LEN))


class APIKeyUnicityError(Exception):
    """Invoked when trying to create a key and one already exists for user"""


def create_api_key(cauth_id):
    if get_api_key_from_cauth_id(cauth_id):
        raise APIKeyUnicityError('Only one key per user allowed')
    key = gen_state(API_KEY_LEN)
    cm = api_keys(cauth_id=cauth_id, key=key)
    Session.add(cm)
    Session.commit()
    return key


def get_cauth_id_from_api_key(key):
    try:
        result = Session.query(api_keys).filter_by(key=key).one()
        return result.cauth_id
    except NoResultFound:
        return None


def get_api_key_from_cauth_id(cauth_id):
    try:
        result = Session.query(api_keys).filter_by(cauth_id=cauth_id).one()
        return result.key
    except NoResultFound:
        return None


def delete_api_key(cauth_id):
    try:
        result = Session.query(api_keys).filter_by(cauth_id=cauth_id)
        result.delete()
    except NoResultFound:
        # do nothing
        return
