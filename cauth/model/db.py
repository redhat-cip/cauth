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

from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.exc import NoResultFound


Base = declarative_base()
Session = scoped_session(sessionmaker())


STATE_LEN = 16


def gen_state(len):
    lst = [random.choice(string.ascii_letters + string.digits)
           for n in xrange(len)]
    return "".join(lst)


class state_mapping(Base):
    __tablename__ = 'state_mapping'

    index = Column(Integer, primary_key=True)
    state = Column(String(STATE_LEN))
    url = Column(String)


def put_url(url):
    state = gen_state(STATE_LEN)
    cm = state_mapping(state=state, url=url)
    Session.add(cm)
    Session.commit()

    return state


def get_url(state):
    ci = Session.query(state_mapping).filter_by(state=state)
    ret = None if ci.first() is None else ci.first().url
    if ci:
        ci.delete()

    return ret


def reset():
    Session.query(state_mapping).delete()


class auth_mapping(Base):
    __tablename__ = 'auth_mapping'

    cauth_id = Column(Integer, primary_key=True)
    # The IDP auth endpoint should be unique
    domain = Column(String)
    # we cannot be sure every IdP will provide a numeric uid so go with String
    external_id = Column(String)


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
        user = Session.query(auth_mapping).filter_by(cauth_id=cauth_id).one()
        user.delete()
    except NoResultFound:
        # do nothing
        return
