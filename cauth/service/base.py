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


class UserRegistrationError(Exception):
    pass


class ServiceConfigurationError(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class BaseServicePlugin(object):
    """Base class for service plugin."""

    _config_section = "base"

    def __init__(self, conf):
        try:
            self.configure_plugin(conf)
        except AttributeError:
            raise Exception(repr(conf))

    def configure_plugin(self, conf):
        try:
            self.conf = conf[self._config_section]
        except KeyError:
            msg = ("The %s service is not configured" % self._config_section)
            raise ServiceConfigurationError(msg)

    @abc.abstractmethod
    def register_new_user(self, user):
        """Called at login, to register the user if it is her first time
        using the service.
        :param user: a dictionary containing the user's properties"""
        raise NotImplementedError

#    @abc.abstractmethod
#    def logout_from_service(self, *args, **kwargs):
#        """Actions to take when logging out from the service."""
#        raise NotImplementedError
