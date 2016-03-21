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

from sqlalchemy import create_engine, exc, event
from pecan import conf

from cauth.model.db import reset, Base, Session


def create_from_conf():
    configs = dict(conf.sqlalchemy)
    url = configs.pop('url')
    return create_engine(url, pool_recycle=600, **configs)


def checkout_listener(dbapi_con, con_record, con_proxy):
    try:
        try:
            dbapi_con.ping(False)
        except TypeError:
            dbapi_con.ping()
    except dbapi_con.OperationalError as e:
        if e.args[0] in (2006,   # MySQL server has gone away
                         2013,   # Lost connection to server during query
                         2055):  # Lost connection to server
        # caught by pool, which will retry with a new connection
            raise exc.DisconnectionError()
        else:
            raise


def init_model():
    engine = create_from_conf()
    conf.sqlalchemy.engine = engine
    url = dict(conf.sqlalchemy)['url']
    if url.startswith('mysql'):
        event.listen(engine, 'checkout', checkout_listener)
    engine.connect()
    # create the tables if not existing
    Base.metadata.create_all(engine)

    start()
    reset()
    clear()


def start():
    Session.bind = conf.sqlalchemy.engine


def commit():
    Session.commit()


def rollback():
    Session.rollback()


def clear():
    Session.remove()
