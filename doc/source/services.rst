.. toctree::

Supported components
====================

Hooks are defined in cauth for the following components, so that when a successful
authentication occurs in cauth for the first time, the user will be added to the
component's user backend.

Gerrit
------

Gerrit is a free and open source, web-based team code collaboration and reviewing
tool.

Configuration
.............

Add the HTTP auth to the gerrit config file:

.. code-block:: guess

  [auth]
      type = HTTP

on cauth
,,,,,,,,

Add the following section to cauth's config.py:

.. code-block:: python

  gerrit = {
      'url': 'http://gerrit.url',
      'admin_user': 'admin',
      'admin_password': 'password',
      'db_host': 'gerrit_mysql_address',
      'db_name': 'gerrit_mysql_db',
      'db_user': 'gerrit_mysql_username',
      'db_password': 'gerrit_sql_pwd'
  }

* **url** is the gerrit URL
* **admin_user** is the gerrit admin account
* **admin_password** is the gerrit admin password
* **db_host** is the network address of the gerrit mysql backend
* **db_name** is the name of the database used by gerrit
* **db_user** and **db_password** are the credentials used by gerrit with the database

Redmine
-------

Redmine is a free and open source, web-based project management and issue
tracking tool.

Configuration
.............

You need to install the `redmine_http_auth plugin <https://github.com/AdamLantos/redmine_http_auth>`_.

Once it is installed, enable the HTTP authentication in the settings page of the
plugin menu.

on cauth
,,,,,,,,

Add the following section to cauth's config.py:

.. code-block:: python

  redmine = {
    'apihost': 'redmine_api_host',
    'apiurl': '',
    'apikey': '',
  }

* **apihost** is the redmine API host,
* **apiurl** is the redmine API URL endpoint,
* **apikey** is the API key to use to perform user management on redmine
