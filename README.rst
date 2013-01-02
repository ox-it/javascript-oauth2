javascript-oauth2
=================

An implementation of an OAuth2 client in pure JavaScript for web applications,
licensed under the `3-clause BSD license
<http://opensource.org/licenses/BSD-3-Clause>`_.

Overview
--------

Provides a ``window.OAuth2`` class with an ``ajax()`` method for making
OAuth2-protected requests.

Here's the feature list:

* Transparently handles ``401 Unauthorized`` responses from the remote web service.
* Provides a hook for the application to prompt the user to visit the remote web service to authorize the application.
* Transparently refreshes expired access tokens if a refresh token has previously been provided.
* Wraps the `jQuery ajax() method <http://api.jquery.com/jQuery.ajax/>`_.


Requirements
------------

The remote web service and browser must both support `Cross-Origin Resource
Sharing (CORS) <http://www.html5rocks.com/en/tutorials/cors/>`_.

On the web service side, it must minimally add the following headers::

   Access-Control-Allow-Origin: https://your-domain
   Access-Control-Expose-Headers: WWW-Authenticate

The web service must respond to requests requiring authentication with ``401
Unauthorized``, not a redirect to a login form. In time, we should support
pre-emptive authorization and checking for login page redirects.

The ``OAuth2.ajax()`` method is a drop-in replacement for ``jQuery.ajax()``,
and introduces a dependency on `jQuery <http://jquery.com/>`_. In time this
should be replaced with a wrapper around ``XMLHttpRequest``, which can be
passed to ``jQuery.ajax()``, but doesn't depend on it.

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

Example
-------

Here's a minimal example:

.. code:: javascript

   var oauth2 = new OAuth2({
       authorizeEndpoint: "https://example.com/oauth2/authorize",
       tokenEndpoint: "https://example.com/oauth2/token",
       consumerKey: "client id",
       consumerSecret: "client secret",
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
   )};

   oauth2.ajax({
       url: "https://example.com/protected-resource",
       success: function(data) { alert("We have data!"); },
       error: function(xhr, textStatus, errorThrown) { alert("Something went wrong: " + textStatus); }
   });

