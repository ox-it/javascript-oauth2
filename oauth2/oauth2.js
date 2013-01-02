/* Copyright (c) 2012, University of Oxford, <opendata@oucs.ox.ac.uk>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE UNIVERSITY OF OXFORD BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

(function() {
    window.OAuth2 = function (options) {
        var that = this;
        this.defaultOptions = {
            authorizeWindowWidth: 500,
            authorizeWindowHeight: 500,
        };
            
        this.options = $.extend({}, this.defaultOptions, options);
        this.accessTokenParamName = options.localStoragePrefix+'access-token';
        this.refreshTokenParamName = options.localStoragePrefix+'refresh-token';

        this.getURLParameter = function(search, name) {
            var part = search.match(RegExp("[?|&]"+name+'=(.*?)(&|$)'));
            if (part) return decodeURIComponent(part[1]);
        };
        
        this.getAccessToken  = function() { return window.localStorage.getItem(that.accessTokenParamName); };
        this.getRefreshToken = function() { return window.localStorage.getItem(that.refreshTokenParamName); };
        this.setAccessToken  = function(value) { return window.localStorage.setItem(that.accessTokenParamName , value); };
        this.setRefreshToken = function(value) { return window.localStorage.setItem(that.refreshTokenParamName, value); };
        this.removeAccessToken  = function() { return window.localStorage.removeItem(that.accessTokenParamName); };
        this.removeRefreshToken = function() { return window.localStorage.removeItem(that.refreshTokenParamName); };
        
        this.parseAuthenticateHeader = function(value, scheme) {
        if (!value) return null;
            var re = /([a-z_\d]+)(=("([^\\"]*(\\.)?)*")|[a-z_\d]*)?(,)?(\s+|$)/i;
            var methods = [], method = null;
            while (value.length) {
                var term = re.exec(value);
                value = value.substr(term[0].length);
                if (!term[6] && term[7]) {
                    method = {scheme: term[1], params: {}};
                    methods.push(method);
                } else {
                    if (term[3].match(/^"/)) term[3] = term[3].substr(1, term[3].length-2);
                    method.params[term[1]] = term[3].replace(/\\"/, '"');
                }
            }
            if (scheme) {
                for (var i=0; i<methods.length; i++)
                    if (methods[i].scheme == scheme)
                        return methods[i].params;
                return null;
            } else
                return methods;
        };

        this.requestAuthorization = function(options) {
            that.options.requestAuthorization(function() {
                that.authorize(options);
            });
        };

        that.authorize = function(options) {
            window.oauthAuthorizationResponse = function(search) {
                window.setTimeout(function() {
                    that.authorizationResponse(search, options);
                }, 0);
            };
            var authorizeURL = that.options.authorizeEndpoint + '?' + $.param({
                response_type: "code",
                client_id: that.options.consumerKey,
                redirect_uri: window.location.toString()
            });
            window.open(authorizeURL,
                        'oauth-authorize',
                        'width=' + that.options.authorizeWindowWidth
                     + ',height=' + that.options.authorizeWindowHeight
                     + ',left=' + (screen.width - that.options.authorizeWindowWidth) / 2
                     + ',top=' + (screen.height - that.options.authorizeWindowHeight) / 2
                     + ',menubar=no,toolbar=no');
        };
        
        this.authorizationResponse = function(search, options) {
            $.ajax(that.options.tokenEndpoint, {
                type: 'POST',
                dataType: 'json',
                data: {
                    client_id: that.options.consumerKey,
                    client_secret: that.options.consumerSecret,
                    grant_type: 'authorization_code',
                    code: that.getURLParameter(search, 'code'),
                    redirect_uri: window.location.toString()
                },
                success: function(data) {
                    that.setAccessToken(data.access_token || '');
                    that.setRefreshToken(data.refresh_token || '');
                    that.ajax(options);
                }
            });
        };
        
        this.refreshAccessToken = function(options) {
            $.ajax(that.options.tokenEndpoint, {
                type: 'POST',
                dataType: 'json',
                data: {
                    client_id: that.options.consumerKey,
                    client_secret: that.options.consumerSecret,
                    grant_type: 'refresh_token',
                    refresh_token: that.getRefreshToken(),
                },
                success: function(data) {
                    that.setAccessToken(data.access_token || '');
                    that.setRefreshToken(data.refresh_token || '');
                    that.ajax(options);
                },
                error: function(xhr, textStatus, errorThrown) {
                    that.removeRefreshToken();
                    that.requestAuthorization(options);
                }
            });
        };
        
        this.ajax = function(options) {
            var accessToken = that.getAccessToken();
            var extraHeaders = accessToken ? { "Authorization": "Bearer " + accessToken } : {};
            var newOptions = $.extend({}, options, {
                error: function(xhr, textStatus, errorThrown) {
                    var bearerParams = that.parseAuthenticateHeader(xhr.getResponseHeader('WWW-Authenticate'), 'Bearer')
                    var headersExposed = !!xhr.getAllResponseHeaders(); // this is a hack for Firefox
                    var bubbleError = false;
                    if (xhr.status == 401) {
                        if (bearerParams && bearerParams.error == undefined) {
                            that.requestAuthorization(options);
                        } else if (((bearerParams && bearerParams.error == "invalid_token") || !headersExposed) && that.getRefreshToken()) {
                            that.removeAccessToken(); // It doesn't work any more.
                            that.refreshAccessToken(options);
                        } else if (!headersExposed && !that.getRefreshToken()) {
                            that.requestAuthorization(options);
                        } else
                            bubbleError = true;
                    } else
                        bubbleError = true;
                    if (bubbleError && options.error) {
                        // Nothing more we can do; pass the error on.
                        options.error(xhr, textStatus, errorThrown);
                    }
                },
                headers: $.extend({}, options.headers || {}, extraHeaders)
            });
            $.ajax(newOptions);
        };
    };
    
    if (window.opener && window.opener.oauthAuthorizationResponse) {
        window.opener.oauthAuthorizationResponse(window.location.search);
        window.close();
    }
})();

