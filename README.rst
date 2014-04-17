javascript-oauth2
=================

An implementation of an OAuth2 client in pure JavaScript for web applications,
licensed under the `3-clause BSD license
<http://opensource.org/licenses/BSD-3-Clause>`_.

Overview
--------

Provides a ``window.oauth2`` object, containing a ``OAuth2XMLHttpRequest``
class implementing the XMLHttpRequest interface for making OAuth2-protected
requests.

Here's the feature list:

* Transparently handles ``401 Unauthorized`` responses from the remote web service.
* Provides a hook for the application to prompt the user to visit the remote web service to authorize the application.
* Transparently refreshes expired access tokens if a refresh token has previously been provided.
* Wraps a ``XMLHttpRequest`` or ``XDomainRequest`` object, or something that acts like one.
* Supports `Bearer authentication <http://tools.ietf.org/html/rfc6750>`_.


Requirements
------------

The remote web service and browser must both support `Cross-Origin Resource
Sharing (CORS) <http://www.html5rocks.com/en/tutorials/cors/>`_ on the
protected resource.

The OAuth2 token endpoint should ideally return the following headers with their responses::

   Access-Control-Allow-Origin: https://your-domain
   Access-Control-Expose-Headers: WWW-Authenticate

All is not lost if it doesn't; the library will make intelligent guesses in the dark.

Each protected resource must support `preflighted requests
<http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_. Here's an
example request and response::

   OPTIONS /protected-resource
   Access-Control-Request-Headers: authorization
   Access-Control-Request-Method: PUT

   Allow: GET,POST,PUT,DELETE,HEAD
   Access-Control-Allow-Headers: authorization
   Access-Control-Allow-Methods: GET,POST,PUT,DELETE,HEAD
   Access-Control-Allow-Origin: https://your-domain
   Access-Control-Expose-Headers: WWW-Authenticate

It may be simplest to mirror the ``Access-Control-Request-Headers`` request
header to the ``Access-Control-Allow-Headers`` response header, and to
duplicate the ``Allow`` response header (listing all available methods) to the
``Access-Control-Allow-Methods`` response header. Note that the response should
be a ``200 OK`` or ``204 No Content``, even if a non-OPTIONS request would
return ``401 Unauthorized``.

The web service must respond to requests requiring authentication with ``401
Unauthorized``, not a redirect to a login form. In time, we should support
pre-emptive authorization and checking for login page redirects.

You can use ``OAuth2XMLHttpRequest`` with `jQuery <http://jquery.com/>`_ like
this:

.. code:: javascript

   $.ajax('https://example.com/', {
       xhr: oauth2.factory({
           authorizeEndpoint: 'https://example.com/oauth2/authorize',
           tokenEndpoint: 'https://example.com/oauth2/token',
           clientID: 'abcdefgh',
           clientSecret: 'ijklmnop',
           localStoragePrefix: 'oauth2.com.example'
       },
       ...
   });


Browser support
---------------

This has been tested in:

* Google Chrome 23
* Firefox 17 (``xhr.getResponseHeader()`` support on CORS requests is broken, but worked around)
* Opera 12

It is believed that it should work in:

* Internet Explorer 8+

It does not work in:

* Android 2.3.3 Browser (intercepts the 401 response before we can do anything about it)


Security considerations
-----------------------

If your web application is served over HTTP, an attacker will be able to
intercept the OAuth2 authorization code added to the redirection URI. See
`Section 4.12 of the OAuth 2.0 specification
<http://tools.ietf.org/html/rfc6749#section-4.1.2>`_ for further details. If
your application is on the public web, an attacker will also have access to the
client secret, and will be able to combine them to request an access token in
order to imitate the authenticated user. It is strongly RECOMMENDED that your
application is served over HTTPS.

If your application is served from the same domain as untrusted code (such as
when using Apache's `UserDir directive
<http://httpd.apache.org/docs/2.4/howto/public_html.html>`_ to host sites at
e.g. ``http://users.example.org/~alice/``), that other code will be able to
access the OAuth2 access token from local storage, and will be able to make
authenticated requests. It is strongly RECOMMENDED that all JavaScript on your
application's domain is trusted.


Example
-------

Here's a minimal example:

.. code:: javascript

   var xhr = new oauth.OAuth2HttpRequest({
       authorizeEndpoint: "https://example.com/oauth2/authorize",
       tokenEndpoint: "https://example.com/oauth2/token",
       clientID: "client id",
       clientSecret: "client secret",
       localStoragePrefix: "oauth2.example.", // Used for storing credentials in localStorage
       requestAuthorization: function(callback) {
           /* This function will be called if the user is required to visit the *
            * remote web service to authorize the application. If the user      *
            * consents, call callback() to open a pop-up window.                */

           // Let's use the jQuery UI dialog (http://jqueryui.com/dialog/)
           $('#dialog-authorize').dialog({
               resizable: false,
               width: 500,
               modal: true,
               buttons: {
                   "Proceed": function() {
                       $(this).dialog("close"); 
                       callback();
                   },
                   "Cancel": function() {
                       $(this).dialog("close");
                   }
               }
           }); 
       }
   });

   xhr.onreadystatechange = function() {
      // get something
   };
   xhr.open('GET', 'https://example.com/protected-resource');
   xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
   xhr.send('param=value&otherparam=othervalue');

