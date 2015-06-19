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


import abc
import six


class AuthProtocolNotAvailableError(Exception):
    pass


class UnauthenticatedError(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class AuthProtocolPlugin(object):
    """Base plugin for authentication protocols.
    """

    _config_section = "base"

    def __init__(self, conf):
        try:
            self.configure_plugin(conf.auth)
        except AttributeError:
            raise Exception(repr(conf))

    def configure_plugin(self, conf):
        try:
            self.conf = conf[self._config_section]
        except KeyError:
            msg = ("The %s authentication protocol "
                   "is not available" % self._config_section)
            raise AuthProtocolNotAvailableError(msg)

    @abc.abstractmethod
    def authenticate(self, **auth_context):
        """authenticate the user for the given auth protocol.
        :param auth_context: the authentication context
        :returns: a dictionary with the user's information:
               {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys}
        :raises: UnauthenticatedError
        """
