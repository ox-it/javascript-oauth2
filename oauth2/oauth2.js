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

	var xhr = function (options) {
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

	xhr.prototype._defaultOptions = {
		authorizeWindowWidth: 500,
		authorizeWindowHeight: 500,
		xmlHttpRequest: function() { return new (window.XDomainRequest != undefined ? XDomainRequest : XMLHttpRequest); },
		supportsCORS: window.XDomainRequest != undefined || "withCredentials" in XMLHttpRequest,
		localStoragePrefix: 'oauth2.'
	};

	// Utility methods

	xhr.prototype._extend = function () {
		var obj = arguments[0];
		for (var i=1; i<arguments.length; i++)
			for (var k in arguments[i])
				obj[k] = arguments[i][k];
		return obj;
	};

	xhr.prototype._getURLParameter = function(search, name) {
		var part = search.match(RegExp("[?|&]"+name+'=(.*?)(&|$)'));
		if (part) return decodeURIComponent(part[1]);
  	};

	xhr.prototype._parseAuthenticateHeader = function(value, scheme) {
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

	xhr.prototype._param = function(data) {
		var result = "";
		for (var key in data) {
			if (result) result += "&";
			result += key;
			result += "=";
			result += encodeURIComponent(data[key]);
		}
		return result;
	};

	xhr.prototype._getAccessToken  = function() { return window.localStorage.getItem(this._accessTokenParamName); };
	xhr.prototype._getRefreshToken = function() { return window.localStorage.getItem(this._refreshTokenParamName); };
	xhr.prototype._setAccessToken  = function(value) { return window.localStorage.setItem(this._accessTokenParamName , value); };
	xhr.prototype._setRefreshToken = function(value) { return window.localStorage.setItem(this._refreshTokenParamName, value); };
	xhr.prototype._removeAccessToken  = function() { return window.localStorage.removeItem(this._accessTokenParamName); };
	xhr.prototype._removeRefreshToken = function() { return window.localStorage.removeItem(this._refreshTokenParamName); };


	xhr.prototype._requestAuthorization = function() {
		var that = this;
		this._options.requestAuthorization(function() {
			that._authorize();
		});
	};

	xhr.prototype._onreadystatechange = function() {
		this.readyState = this._xhr.readyState;
		if (this._xhr.readyState >= 2) {
			this.status = this._xhr.status;
			this.statusText = this._xhr.statusText;
		}
		if (this._xhr.readyState >= 3) {
			this.response = this._xhr.response;
			this.responseText = this._xhr.responseText;
			this.responseType = this._xhr.responseType;
			this.responseXML = this._xhr.responseXML;
		}

		if (this._xhr.readyState == this._xhr.DONE && this._xhr.status == 401) {
			this._authorize();
		}

		// Don't duplicate these events if we're having a second attempt
		if (this._replaying && this._xhr.readyState <= 2)
			return;
		// Don't pass on if we're seeking authorization
		if (this._xhr.readyState >= 3 && this._xhr.status == 401)
			return;

		// Pass it onwards.
		if (this.onreadystatechange)
			this.onreadystatechange.apply(this);

	};

	xhr.prototype._authorize = function() {
		console.log('authorize');
		var that = this;
		window.oauthAuthorizationResponse = function(window, search) {
			if (window == that._authorizationWindow)
				that._authorizationResponse(search);
		};
		var authorizeURL = this._options.authorizeEndpoint + '?' + this._param({
			response_type: "code",
			client_id: this._options.consumerKey,
			redirect_uri: window.location.toString()
		});
		this._authorizationWindow = window.open(authorizeURL, 'oauth-authorize',
			'width=' + this._options.authorizeWindowWidth
			+ ',height=' + this._options.authorizeWindowHeight
			+ ',left=' + (screen.width - this._options.authorizeWindowWidth) / 2
			+ ',top=' + (screen.height - this._options.authorizeWindowHeight) / 2
			+ ',menubar=no,toolbar=no');
		};

	xhr.prototype._authorizationResponse = function(search, options) {
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
			client_id: this._options.consumerKey,
			client_secret: this._options.consumerSecret,
			grant_type: 'authorization_code',
			code: this._getURLParameter(search, 'code'),
			redirect_uri: window.location.toString()
		}));
		this._replay();
	};

	xhr.prototype._refreshAccessToken = function(options) {
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
			client_id: this._options.consumerKey,
			client_secret: this._options.consumerSecret,
			grant_type: 'refresh_token',
			refresh_token: this._getRefreshToken()
		}));
	};

	xhr.prototype._replay = function() {
		console.log("replay");
		if (this._xhr.status > 0)
			this.abort();
		this._replaying = true;
		this.open.apply(this, this._openArguments);
		for (var i=0; i<this._headers.length; i++)
			this._xhr.setRequestHeader.apply(this._xhr, this._headers[i]);
		this.send.apply(this, this._sendArguments);
	}

	xhr.prototype.abort = function() {
		console.log("abort");
		this._xhr.abort();
		this._replaying = false;
	};

	xhr.prototype.setRequestHeader = function(header, value) {
		this._headers.push(arguments);
		this._xhr.setRequestHeader(header, value);
	}

	xhr.prototype.open = function(method, url, async) {
		console.log("open");
		this._openArguments = arguments;
		this._xhr.open(method, url, async);
	};

	xhr.prototype.send = function(data) {
		console.log("send");
		this._sendArguments = arguments;
		var accessToken = this._getAccessToken();
		if (accessToken)
			this._xhr.setRequestHeader("Authorization", "Bearer " + accessToken);

		this._xhr.send(data);

		return;
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

	window.oauth2 = {
		OAuth2XMLHttpRequest: xhr,
		factory: function(options) { return new xhr(options); }
	};

	// Pass the authorization back to the opener if necessary.
	if (window.opener && window.opener.oauthAuthorizationResponse) {
		window.opener.oauthAuthorizationResponse(window, window.location.search);
		window.close();
	}

})();

