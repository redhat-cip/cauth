.. toctree::

Installation
============

cauth main server
-----------------

You will need the following components:

* Apache with mod_wsgi
* mod_auth_pubtkt
* cauth

Install Apache
..............

Apache is most likely packaged for your operating system. Please refer to your
OS's documentation to proceed.

On Fedora/CentOS (you might need to enable the EPEL repository):

.. code-block:: bash

   sudo yum install httpd mod_wsgi

On Debian/Ubuntu:

.. code-block:: bash

   sudo apt-get install apache2 libapache2-mod-wsgi

Installing mod_auth_pubtkt
..........................

You should follow the steps described in `mod_auth_pubtkt's documentation <https://neon1.net/mod_auth_pubtkt/install.html>`_.

Basically, download the lastest version of mod_auth_pubtkt at https://neon1.net/mod_auth_pubtkt/download.html and then:

.. code-block:: bash

   tar xzfv mod_auth_pubtkt-x.y.z.tar.gz
   cd mod_auth_pubtkt-x.y.z
   ./configure --apxs=/usr/bin/apxs

That last step might require some extra dependencies that can be found in the
development packages for apache. Refer to your OS to find out which packages are
needed.

On debian and ubuntu:

* apache-dev
* gcc
* openssl-dev

On CentOS:

* http-devel
* gcc
* make
* openssl-devel
* openssl

Then, finally:

.. code-block:: bash

   make
   make install

You will also need openssl to generate keypairs. Refer to your OS's documentation
to find out the best way to install this.

Installing cauth
................

Make sure you have the following tools installed on your system before proceeding:

* git
* python development files: python-dev (debian) or python-devel (CentOS)
* pip: package python-pip (debian) or

.. code-block:: bash

   curl -o get-pip.py https://bootstrap.pypa.io/get-pip.py && python ./get-pip.sh

* ldap, mysql and sasl development files (on CentOS: openldap-devel, mariadb-devel, m2crypto)

Clone the cauth repository and check out the version you want to use, then
use the installation script to add the library to your system:

.. code-block:: bash

   git clone http://softwarefactory.enovance.com/r/p/cauth.git
   cd cauth
   git checkout 0.3.0
   pip install . -r requirements.txt


Components
----------

The components will need the following parts:

* Apache
* mod_auth_pubtkt
* of course, the components you want to use

Follow the previous instructions to complete the installation.
