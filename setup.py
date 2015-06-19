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

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

try:
    import multiprocessing  # noqa
except:
    pass


VERSION = '0.3.0'


# use requirements.txt for install
INSTALL_REQUIRES = []


setup(
    name='cauth',
    version=VERSION,
    description='Multiprotocol SSO auth frontend for other services',
    author='Software Factory',
    author_email='softwarefactory@enovance.com',
    test_suite='nose.collector',
    zip_safe=False,
    include_package_data=True,
    package_data={'cauth': ['template/*', ]},
    packages=find_packages(exclude=['ez_setup']),

    install_requires=INSTALL_REQUIRES,
    url='http://softwarefactory.enovance.com/r/gitweb?p=cauth.git;a=summary',
    download_url='https://github.com/enovance/cauth/tarball/%s' % VERSION,
    keywords=['software factory', 'SSO', 'Authentication'],

    entry_points={
        'cauth.authentication': [
            ('GithubPersonalAccessToken = '
             'cauth.auth.github:GithubPersonalAccessTokenAuthPlugin'),
            ('Github = cauth.auth.github:GithubAuthPlugin'),
            ('Password = cauth.auth.password:PasswordAuthPlugin')
        ]
    },
)
