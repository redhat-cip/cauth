Configuration
=============

cauth main server
-----------------

auth_pubtkt
...........

You need to generate a key pair so that the cookie can be signed and validated
by the components:

.. code-block:: bash

  mkdir /srv/cauth_keys
  openssl dsaparam -out dsaparam.pem 1024
  openssl gendsa -out /srv/cauth_keys/privkey.pem dsaparam.pem
  openssl dsa -in /srv/cauth_keys/privkey.pem -out /srv/cauth_keys/pubkey.pem -pubout

Apache
......

#. activate the WSGI module with the command (debian):

.. code-block:: bash

   a2enmod wsgi

#. If you are using CentOS, make sure your httpd configuration contains the
   following line:

.. code-block:: apache

  LoadModule wsgi_module modules/mod_wsgi.so

#. Create a directory called cauth in /var/www/
#. Copy the files app.wsgi and config.py from etc/ to /var/www/cauth/, and make
   sure these files belong to the www user
#. Use the template etc/cauth.site to configure your website so that cauth is
   available. Adapt it according to your needs; the template will point the
   cauth requests to http://your.domain.url/auth

cauth
.....

The following elements in cauth's config.py can be configured:

.. code-block:: python

   app = {
    # ...
    'priv_key_path': '/srv/cauth_keys/privkey.pem',
    'cookie_domain': 'tests.dom',
    'debug': False,
    'cookie_period': 43200
   }

* **privkey** is the path to the private key generated earlier
* **cookie_domain** is the domain to use for the authentication cookie
* **cookie_period** is the amount of seconds the cookie will be valid (defaults
  to 12 hours)

Also make sure that the paths and files used for logging (/var/log/cauth/cauth.log by default)
and the internal sqlite database (/var/lib/cauth/ by default) exist and are writable
by the www or apache user, depending on your installation.

Components
----------

Make sure your component supports the HTTP authentication (that is, delegating
authentication to the container web server that will set the REMOTE_USER
variable). This configuration steps varies with each component, so please refer
to your component's documentation.

Apache serving components
.........................

#. If the component is served by a different instance of Apache than cauth, copy
   the public key you generated earlier on the component's host. In the
   configuration templates, it is assumed that the key will be stored a
   /srv/cauth_keys/pubkey.pem
#. Use the template etc/component.site to configure your website so that cauth is
   available. Adapt it according to your needs. You will want to modify this:

.. code-block:: apache

   TKTAuthLoginURL http://your.domain.url/auth/login

Depending on how you configured the cauth service.
