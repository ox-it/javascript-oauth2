/*! Copyright (c) 2012, University of Oxford, <opendata@oucs.ox.ac.uk>
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
		this._options = this._extend({}, this._defaultOptions, options || {});
		this._accessTokenParamName = this._options.localStoragePrefix+'access-token';
		this._refreshTokenParamName = this._options.localStoragePrefix+'refresh-token';
		this._authorizationWindow = null;
		this._xhr = this._options.xmlHttpRequest();
		this._replaying = false;

		var that = this;
		this._xhr.onreadystatechange = function() { that._onreadystatechange.apply(that); };
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
		xmlHttpRequest: function() { return new (window.XDomainRequest != undefined ? XDomainRequest : XMLHttpRequest); },
		supportsCORS: window.XDomainRequest != undefined || "withCredentials" in XMLHttpRequest,
		// Override to ask user for permission before calling authorize()
		requestAuthorization: function(authorize) { authorize(); },
		localStoragePrefix: 'oauth2.'
	},

	// Utility methods

	_extend: function () {
		var obj = arguments[0];
		for (var i=1; i<arguments.length; i++)
			for (var k in arguments[i])
				obj[k] = arguments[i][k];
		return obj;
	},

	_getURLParameter: function(search, name) {
		var part = search.match(RegExp("[?|&]"+name+'=(.*?)(&|$)'));
		if (part) return decodeURIComponent(part[1]);
  	},

	_parseAuthenticateHeader: function(value, scheme) {
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

	_getAccessToken:     function() { return window.localStorage.getItem(this._accessTokenParamName); },
	_getRefreshToken:    function() { return window.localStorage.getItem(this._refreshTokenParamName); },
	_setAccessToken:     function(value) { return window.localStorage.setItem(this._accessTokenParamName , value); },
	_setRefreshToken:    function(value) { return window.localStorage.setItem(this._refreshTokenParamName, value); },
	_removeAccessToken:  function() { return window.localStorage.removeItem(this._accessTokenParamName); },
	_removeRefreshToken: function() { return window.localStorage.removeItem(this._refreshTokenParamName); },


	_requestAuthorization: function() {
		var that = this;
		this._options.requestAuthorization(function() {
			that._authorize();
		});
	},

	_onreadystatechange: function() {
		var bubble = true;
		var xhr = this._xhr;
		this.readyState = xhr.readyState;


		if (xhr.readyState >= 2) {
			this.status = xhr.status;
			this.statusText = xhr.statusText;
		}
		if (xhr.readyState >= 3) {
			this.response = xhr.response;
			this.responseText = xhr.responseText;
			this.responseType = xhr.responseType;
			this.responseXML = xhr.responseXML;
		}

		if (xhr.readyState == xhr.DONE && xhr.status == 401) {
			var bearerParams = this._parseAuthenticateHeader(this._xhr.getResponseHeader('WWW-Authenticate'), 'Bearer')
			var headersExposed = !!xhr.getAllResponseHeaders(); // this is a hack for Firefox
			if (bearerParams && bearerParams.error == undefined) {
				this._requestAuthorization();
				bubble = false;
			} else if (((bearerParams && bearerParams.error == 'invalid_token') || !headersExposed) && this._getAccessToken()) {
				this._removeAccessToken(); // It doesn't work any more.
				this._refreshAccessToken();
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
			redirect_uri: window.location.toString()
		});
		this._authorizationWindow = window.open(authorizeURL, 'oauth-authorize',
			'width=' + this._options.authorizeWindowWidth
			+ ',height=' + this._options.authorizeWindowHeight
			+ ',left=' + (screen.width - this._options.authorizeWindowWidth) / 2
			+ ',top=' + (screen.height - this._options.authorizeWindowHeight) / 2
			+ ',menubar=no,toolbar=no');
	},

	_authorizationResponse: function(search, options) {
		var req = this._options.xmlHttpRequest();
		var that = this;
		req.open("POST", this._options.tokenEndpoint, false);
		req.setRequestHeader("Accept", "application/json");
		req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		req.onreadystatechange = function() {
			if (req.readyState == req.DONE) {
				var data = JSON.parse(req.responseText);
				that._setAccessToken(data.access_token || '');
				that._setRefreshToken(data.refresh_token || '');

			}
		}
		req.send(this._param({
			client_id: this._options.clientID,
			client_secret: this._options.clientSecret,
			grant_type: 'authorization_code',
			code: this._getURLParameter(search, 'code'),
			redirect_uri: window.location.toString()
		}));
		this._replay();
	},

	_refreshAccessToken: function(options) {
		var req = this._options.xmlHttpRequest();
		var that = this;
		req.onreadystatechange = function() {
			if (req.readyState == req.DONE) {
				if (req.status == 200) {
					var data = JSON.parse(req.responseText);
					that._setAccessToken(data.access_token || '');
					that._setRefreshToken(data.refresh_token || '');
					that._replay();
				} else {
					that._removeRefreshToken();
					that._requestAuthorization();
				}
			}
		};
		req.open('POST', this._options.tokenEndpoint, false);
		req.setRequestHeader("Accept", "application/json");
		req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		req.send(this._param({
			client_id: this._options.clientID,
			client_secret: this._options.clientSecret,
			grant_type: 'refresh_token',
			refresh_token: this._getRefreshToken()
		}));
	},

	_replay: function() {
		if (this._xhr.status > 0)
			this.abort();
		this._replaying = true;
		this.open.apply(this, this._openArguments);
		if (this._overriddenMimeType)
			this._xhr.overrideMimeType(this._overriddenMimeType);
		for (var i=0; i<this._headers.length; i++)
			this._xhr.setRequestHeader.apply(this._xhr, this._headers[i]);
		this.send.apply(this, this._sendArguments);
	},

	abort: function() {
		this._xhr.abort();
		this._replaying = false;
	},

	setRequestHeader: function(header, value) {
		this._headers.push(arguments);
		this._xhr.setRequestHeader(header, value);
	},

	open: function(method, url, async) {
		this._openArguments = arguments;
		if (this.responseType)
			this._xhr.responseType = this.responseType;
		this._xhr.open(method, url, async);
	},

	send: function(data) {
		this._sendArguments = arguments;
		var accessToken = this._getAccessToken();
		if (accessToken)
			this._xhr.setRequestHeader("Authorization", "Bearer " + accessToken);

		this._xhr.send(data);

		return;
	},

	overrideMimeType: function(mime) {
		this._overriddenMimeType = mime;
		this._xhr.overrideMimeType(mime);
	},

	getAllResponseHeaders: function() { return this._xhr.getAllResponseHeaders(); },
	getResponseHeader: function(header) { return this._xhr.getResponseHeader(header); }

	};

	window.oauth2 = {
		OAuth2XMLHttpRequest: OAuth2XMLHttpRequest,
		factory: function(options) { return function() { return new OAuth2XMLHttpRequest(options); }; }
	};

	// Pass the authorization back to the opener if necessary.
	if (window.opener && window.opener.oauthAuthorizationResponse) {
		window.opener.oauthAuthorizationResponse(window, window.location.search);
		window.close();
	}

})();

