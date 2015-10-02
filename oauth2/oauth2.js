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
	var authorizationResponseEventName = 'oauth2-authorization-response';
	var requiredOptions = ['clientID', 'clientSecret', 'authorizeEndpoint', 'tokenEndpoint'];

	var OAuth2XMLHttpRequest = function (options) {
		for (var i=0; i<requiredOptions.length; i++)
			if (options[requiredOptions[i]] == undefined)
				throw new Error(requiredOptions[i] + ' not defined for OAuth2');

		this._headers = [];
		this._openArguments = null;
		this._sendArguments = null;
		this._options = _.extend({}, this._defaultOptions, options || {});
		this._accessTokenParamName = this._options.localStoragePrefix+'access-token';
		this._refreshTokenParamName = this._options.localStoragePrefix+'refresh-token';
		this._accessTokenExpiryParamName = this._options.localStoragePrefix+'access-token-expiry';
		this._authMechanismParamName = this._options.localStoragePrefix+'auth-mechanism';
		this._authorizationWindow = null;
		this._instantiateXHR();
		this._replaying = false;

	};

	OAuth2XMLHttpRequest.prototype = {

	UNSENT: 0,
	OPENED: 1,
	HEADERS_RECEIVED: 2,
	LOADING: 3,
	DONE: 4,

	_defaultOptions: {
		authorizeWindowWidth: 500,
		authorizeWindowHeight: 500,
		xmlHttpRequest: function() {
			if (XMLHttpRequest.withCredentials)
				return new XMLHttpRequest();
			if (window.XDomainRequest)
				return new XDomainRequest();
			else
				return new XMLHttpRequest();
		},
		supportsCORS: window.XDomainRequest != undefined || "withCredentials" in XMLHttpRequest,
		// Override to ask user for permission before calling authorize()
		requestAuthorization: function(authorize) { authorize(); },
		localStoragePrefix: 'oauth2.',
		error: function(type, data) { console.log(["OAuth2 error", type, data]); },
		redirectURI: window.location.toString(),
		// Override to use a different name for the WWW-Authenticate header (necessary for cordova on iOS)
		renameWWWAuthenticateHeader: null
	},

	_instantiateXHR: function() {
		this._xhr = this._options.xmlHttpRequest();
		this._is_xdr = window.XDomainRequest && this._xhr instanceof window.XDomainRequest;

		this._xhr.onreadystatechange = _.bind(function() {
			this._onreadystatechange.apply(this);
		}, this);

		if (this._is_xdr) {
			this._xhr.onload = function() {
				this.readyState = OAuth2XMLHttpRequest.prototype.DONE;
				this.status = 200; this.statusText = 'OK';
				this.onreadystatechange();
			};
			this._xhr.onerror = function() {
				this.readyState = OAuth2XMLHttpRequest.prototype.DONE;
				this.status = 401; this.statusText = 'Unauthorized (we assume)';
				this.onreadystatechange();
			};
		}
	},

	// Utility methods

	_getURLParameter: function(search, name) {
		var part = search.match(RegExp("[?|&]"+name+'=(.*?)(&|$)'));
		if (part) return decodeURIComponent(part[1]);
  	},

	_parseAuthenticateHeader: function(value, scheme) {
		if (!value) return null;

                var _tokens = [
                    ['token', /^([!#$%&'*+\-.^_`|~\w\/]+(?:={1,2}$)?)/],
                    ['token', /^"(([^"\\]|\\\\|\\")+)"/],
                    [null, /^\s+/],
                    ['equals', /^(=)/],
                    ['comma', /^(,)/],
                ];

                // Tokenize
                var tokens = [];
                while (value.length) {
                    for (var i=0; i<_tokens.length; i++) {
                        var name = _tokens[i][0], pattern = _tokens[i][1];
                        var match = pattern.exec(value);
                        if (match) {
                            if (name)
                                tokens.push([name, match[1]]);
                            value = value.substr(match[0].length);
                            break;
                        }
                    }
                    if (i == _tokens.length) // Ran out of patterns
                        return null;
                }

                // Join name-value pairs
                for (var i=0; i<tokens.length-2; i++) {
                    if (tokens[i  ][0] == 'token' &&
                        tokens[i+1][0] == 'equals' &&
                        tokens[i+2][0] == 'token') {
                        var pair = {};
                        pair[tokens[i][1]] = tokens[i+2][1];
                        tokens.splice(i, 3, ['pair', pair]);
                    }
                }

                // Construct challenges
                var groupedChallenges = [];
                while (tokens.length) {
                    var i = 1;
                    if (tokens.length == 1) {}
                    else if (tokens[1][0] == 'comma') {}
                    else if (tokens[1][0] == 'token') {
                        i = 2;
                    } else {
                        while (i < tokens.length && tokens[i][0] == 'pair') {
                            i += 2;
                        }
                        i -= 1;
                    }
                    groupedChallenges.push([tokens[0][1], tokens.slice(1, i)])
                    tokens.splice(0, i + 1);
                }

                var challenges = {};
                for (var i=0; i<groupedChallenges.length; i++) {
                    var args = [], kwargs = {};
                    var name = groupedChallenges[i][0];
                    var tokens = groupedChallenges[i][1];
                    for (var j=0; j<tokens.length; j++) {
                        var token = tokens[j];
                        if (token[0] == 'token')
                            args.push(token[1]);
                        else if (token[0] == 'pair')
                            _.extend(kwargs, token[1]);
                    }
                    challenges[name] = args.length ? args[0] : kwargs;
                }

		if (scheme)
			return challenges[scheme];
		else
			return challenges;
	},

	_param: function(data) {
		var result = "";
		for (var key in data) {
			if (result) result += "&";
			result += key;
			result += "=";
			result += encodeURIComponent(data[key]);
		}
		return result;
	},

	_getAccessToken:          function() { return window.localStorage.getItem(this._accessTokenParamName); },
	_getRefreshToken:         function() { return window.localStorage.getItem(this._refreshTokenParamName); },
	_getAccessTokenExpiry:    function() { return window.localStorage.getItem(this._accessTokenExpiryParamName); },
	_getAuthMechanism:        function() {
		if (this._is_xdr)
			return "param"; // IE's XDomainRequest doesn't support sending headers, so don't try.
		return window.localStorage.getItem(this._authMechanismParamName);
	},
	_setAccessToken:          function(value) { return window.localStorage.setItem(this._accessTokenParamName , value); },
	_setRefreshToken:         function(value) { return window.localStorage.setItem(this._refreshTokenParamName, value); },
	_setAccessTokenExpiry:    function(value) { return window.localStorage.setItem(this._accessTokenExpiryParamName, value); },
	_setAuthMechanism:        function(value) { return window.localStorage.setItem(this._authMechanismParamName, value); },
	_removeAccessToken:       function() { return window.localStorage.removeItem(this._accessTokenParamName); },
	_removeRefreshToken:      function() { return window.localStorage.removeItem(this._refreshTokenParamName); },
	_removeAccessTokenExpiry: function() { return window.localStorage.removeItem(this._accessTokenExpiryParamName); },
	_removeAuthMechanism:     function() { return window.localStorage.removeItem(this._authMechanismParamName); },


	_requestAuthorization: function() {
		var that = this;
		this._options.requestAuthorization(function() {
			return that._authorize();
		});
	},

	_onreadystatechange: function() {
		var bubble = true;
		var xhr = this._xhr;
		this.readyState = xhr.readyState;


		if (xhr.readyState >= this.HEADERS_RECEIVED) {
			this.status = xhr.status;
			this.statusText = xhr.statusText;
		}
		if (xhr.readyState >= this.LOADING) {
			this.response = xhr.response;
			this.responseText = xhr.responseText;
			this.responseType = xhr.responseType;
			this.responseXML = xhr.responseXML;
		}

		if (xhr.readyState == this.DONE && xhr.status == 0) {
			if (this._getAuthMechanism() == 'param') {
				this._error("network-error", null);
			} else {
				this._setAuthMechanism("param");
				bubble = false;
				this._replay();
			}
		} else if (xhr.readyState == this.DONE && xhr.status == 401) {
			var bearerParams, headersExposed = false;
			if (this._getAuthMechanism() != 'param') {
				var authenticateHeaderName = this._options.renameWWWAuthenticateHeader == null ? 'WWW-Authenticate' : this._options.renameWWWAuthenticateHeader;
				bearerParams = this._parseAuthenticateHeader(this._xhr.getResponseHeader(authenticateHeaderName), 'Bearer')
				headersExposed = !this._is_xdr || !!xhr.getAllResponseHeaders(); // this is a hack for Firefox and IE
			}
			if (bearerParams && bearerParams.error == undefined) {
				this._requestAuthorization();
				bubble = false;
			} else if (((bearerParams && bearerParams.error == 'invalid_token') || !headersExposed) && this._getRefreshToken()) {
				this._removeAccessToken(); // It doesn't work any more.
				this._refreshAccessToken({});
				bubble = false;
			} else if (!headersExposed && !this._getRefreshToken()) {
				this._requestAuthorization();
				bubble = false;
			}
		}

		// Don't duplicate these events if we're having a second attempt
		if (this._replaying && this._xhr.readyState <= 2)
			bubble = false;
		// Don't pass on if we're seeking authorization
		if (this._xhr.readyState == 3 && this._xhr.status == 401)
			bubble = false;

		// Pass it onwards.
		if (bubble && this.onreadystatechange)
			this.onreadystatechange.apply(this);

	},

	_authorize: function() {
		var that = this;
		window.oauthAuthorizationResponse = function(window, search) {
			if (window == that._authorizationWindow)
				that._authorizationResponse(search);
		};
		var authorizeURL = this._options.authorizeEndpoint + '?' + this._param({
			response_type: "code",
			client_id: this._options.clientID,
			redirect_uri: this._options.redirectURI,
			scope: (this._options.scopes || []).join(' ')
		});
		this._authorizationWindow = window.open(authorizeURL, 'oauthauthorize',
			'width=' + this._options.authorizeWindowWidth
			+ ',height=' + this._options.authorizeWindowHeight
			+ ',left=' + (screen.width - this._options.authorizeWindowWidth) / 2
			+ ',top=' + (screen.height - this._options.authorizeWindowHeight) / 2
			+ ',menubar=no,toolbar=no');
		return this._authorizationWindow;
	},

	_authorizationResponse: function(search, options) {
		var req = this._options.xmlHttpRequest();
		var that = this;
		var data;
		req.open("POST", this._options.tokenEndpoint, false);
		if (!this._is_xdr) { // Let's try to be explicit
			req.setRequestHeader("Accept", "application/json");
			req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		}
		req.onload = function() {
			if (that._is_xdr || req.readyState == that.DONE) {
				data = JSON.parse(req.responseText);
				if (data.error) {
					that._error("authorize", data);
				} else {
					that._newAccessToken(data);
					that._replay();
				}
			};
		};
		req.send(this._param({
			client_id: this._options.clientID,
			client_secret: this._options.clientSecret,
			grant_type: 'authorization_code',
			code: this._getURLParameter(search, 'code'),
			redirect_uri: this._options.redirectURI
		}));

	},

	_refreshAccessToken: function(options) {
		var req = this._options.xmlHttpRequest();
		var that = this;
		req.onload = function() {
			if (that._is_xdr || req.readyState == that.DONE) {
				data = JSON.parse(req.responseText);
				if (data.error) {
					that._error("refresh", data);
					that._removeRefreshToken();
					that._requestAuthorization();
				} else {
					that._newAccessToken(data);
                                        if (options.replay != false)
						that._replay();
				}
			}
		};
		req.onerror = function() {
			that._error("refresh");
			that._removeRefreshToken();
			that._requestAuthorization();
		};
		req.open('POST', this._options.tokenEndpoint, false);
		if (!this._is_xdr) { // Let's try to be explicit
			req.setRequestHeader("Accept", "application/json");
			req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		}
		req.send(this._param({
			client_id: this._options.clientID,
			client_secret: this._options.clientSecret,
			grant_type: 'refresh_token',
			refresh_token: this._getRefreshToken()
		}));
	},

	_newAccessToken: function(data) {
		this._setAccessToken(data.access_token || '');
		this._setRefreshToken(data.refresh_token || '');
		if (data.expires_in)
			this._setAccessTokenExpiry(Date.now() + data.expires_in * 1000);
		else if (that._getAccessTokenExpiry())
			this._removeAccessTokenExpiry();
	},

	_error: function(type, data) {
		if (this._options.error) this._options.error(type, data);
	},

	_replay: function() {
		this._instantiateXHR();
		this._replaying = true;
		this.open.apply(this, this._openArguments);
		if (this._overriddenMimeType)
			this._xhr.overrideMimeType(this._overriddenMimeType);
		for (var i=0; i<this._headers.length; i++) {
			this._xhr.setRequestHeader.apply(this._xhr, this._headers[i]);
		}
		this.send.apply(this, this._sendArguments);
	},

	abort: function() {
		this._xhr.abort();
		this._replaying = false;
		this._openArguments = null;
		this._overriddenMimeType = null;
		this._headers = [];
		this._sendArguments = null;
	},

	setRequestHeader: function(header, value) {
		this._headers.push(arguments);
		this._xhr.setRequestHeader(header, value);
	},

	open: function(method, url, async) {
                if (async == undefined) async = true;
		this._openArguments = arguments;
		if (this.responseType)
			this._xhr.responseType = this.responseType;

		var accessToken = this._getAccessToken();
		var authMechanism = this._getAuthMechanism();
		var authedURL = (accessToken && authMechanism == 'param') ? this.getAuthorizedURL(url) : url;

		this._xhr.open(method, authedURL, async);
	},

	send: function(data) {
		this._sendArguments = arguments;
		var accessToken = this._getAccessToken();
		var authMechanism = this._getAuthMechanism();

		//optionally add a header to request that the server rename the WWW-Authenticate header in the response
		if(this._options.renameWWWAuthenticateHeader !== null) {
			this._xhr.setRequestHeader('X-Rename-WWW-Authenticate', this._options.renameWWWAuthenticateHeader);
		}

		if (accessToken && (!authMechanism || authMechanism == 'header'))
			this._xhr.setRequestHeader("Authorization", "Bearer " + accessToken);

		return this._xhr.send(data);
	},

	overrideMimeType: function(mime) {
		this._overriddenMimeType = mime;
		this._xhr.overrideMimeType(mime);
	},

	getAllResponseHeaders: function() { return this._xhr.getAllResponseHeaders(); },
	getResponseHeader: function(header) { return this._xhr.getResponseHeader(header); },
	
	getAuthorizedURL: function(url) {
		return url
		     + ((url.indexOf('?') !== -1) ? '&' : '?')
		     + 'bearer_token=' + encodeURIComponent(this._getAccessToken());
	},

	ensureAccessTokenLifetime: function(millis) {
		var expires_at = this._getAccessTokenExpiry();
		if (expires_at && Date.now() + millis > expires_at)
			this._refreshAccessToken({replay: false});
	}

	};

	window.oauth2 = {
		OAuth2XMLHttpRequest: OAuth2XMLHttpRequest,
		factory: function(options) { return function() { return new OAuth2XMLHttpRequest(options); }; },
		authorizationResponse: function() {
			// Pass the authorization back to the opener if necessary.
			if (window.opener && window.opener.oauthAuthorizationResponse) {
				if (window.opener.location.origin == window.location.origin) {
					window.opener.oauthAuthorizationResponse(window, window.location.search);
				window.close();
				} else {
					console.log("Origins don't match; not passing on code.");
				}
			}
		}
	};


})();
