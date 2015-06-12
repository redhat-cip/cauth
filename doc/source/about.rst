.. toctree::

About cauth
===========

Cauth is the authentication component of the `Software Factory <https://softwarefactory.enovance.com>`_ project, a collection
of tools that form a powerful yet easy-to-manage platform to collaborate on
software development and facilitate continuous integration.

Why cauth ?
-----------

Software Factory is the amalgamation of many components, some of which needing
authentication and therefore a base of users. These components are not necessarily
intended to work together, so ensuring a smooth user experience across all
components in terms of authentication can be challenging:

* it might be possible to federate users by having components use the same storage
  backend (LDAP for example), but it implies maintaining or deploying this backend
  if it does not already exist. It is not desirable for lightweight setups
* components might support some SSO protocols like oAuth or OpenID, but they do
  not necessarily support all of them, or not all components necessarily support
  the SSO protocol you'd like to use
* if your SSO settings change, you have to propagate the change to the configuration
  of every service (and know where to do it !)

Cauth was the solution the Software Factory team came up with:

* cauth centralizes all SSO into one place
* cauth is modular enough to support more SSO protocols or user backends
* cauth can be used with any component supporting the HTTP (aka "REMOTE_USER") authentication

How does it work ?
------------------

Cauth relies heavily on the `mod_auth_pubtkt for Apache <https://neon1.net/mod_auth_pubtkt/>`_, and on the fact that the components to protect with SSO can
be served with Apache and support the "REMOTE_USER" authentication method - if
they can be served with Apache, they usually do.

Let's say you want to access a protected resource on a component:

#. mod_auth_pubtkt on the component's Apache server is configured to redirect
   you to the cauth login page
#. you log yourself in using the appropriate authentication protocol
#. cauth issues an pubtkt token as a cookie and redirects you to the original
   protected resource
#. the component's Apache checks the integrity of the cookie thanks to a shared
   secret with the cauth component and authorizes access.

