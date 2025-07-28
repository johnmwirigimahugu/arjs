/**
 * Ar.js
 * Ajax without XML : Asynchronous Javascript and JavaScript/JSON(P)
 *
 * @author Bertrand Chevrier <chevrier.bertrand@gmail.com>
 * @license MIT
 * @version 2.0
 * @updated July 28, 2025
 * @timestamp 03:27 AM EAT, Monday, July 28, 2025
 */
(function(){
    'use strict';

    /**
     * Supported request types.
     */
    var types = ['html', 'json', 'jsonp', 'script'];

    /**
     * Supported HTTP methods.
     */
    var methods = [
        'connect',
        'delete',
        'get',
        'head',
        'options',
        'patch',
        'post',
        'put',
        'trace'
    ];

    /**
     * API entry point.
     * Creates a new Ar object for fluent AJAX requests.
     *
     * @example ar().url('page.html').into('#selector').go();
     *
     * @returns {Ar} the Ar object to build the request.
     */
    var ar = function ar() {
        // Contains all values from setters for this context.
        var data = {
            headers: {},
            csrfToken: null // Added for CSRF support
        };

        // Contains bound events.
        var events = {};

        /**
         * The Ar object provides getter/setter methods and chaining.
         * @typedef {Object} Ar
         */
        var Ar = {
            /**
             * URL getter/setter.
             *
             * @example ar().url('data.json');
             * @throws TypeError
             * @param {String} [url] - The URL to set.
             * @returns {Ar|String} Chains or gets the URL.
             */
            url: function(url) {
                return _chain.call(this, 'url', url, validators.string);
            },

            /**
             * Synchronous request setter (async by default).
             *
             * @example ar().sync(true);
             * @param {Boolean|*} [sync] - True for sync requests.
             * @returns {Ar|Boolean} Chains or gets the sync value.
             */
            sync: function(sync) {
                return _chain.call(this, 'sync', sync, validators.bool);
            },

            /**
             * Cache control setter (true by default).
             *
             * @example ar().cache(false);
             * @param {Boolean|*} [cache] - False to disable caching.
             * @returns {Ar|Boolean} Chains or gets the cache value.
             */
            cache: function(cache) {
                return _chain.call(this, 'cache', cache, validators.bool);
            },

            /**
             * Request type getter/setter.
             *
             * @example ar().type('json');
             * @throws TypeError
             * @param {String} [type] - The type (html, json, jsonp, script).
             * @returns {Ar|String} Chains or gets the type.
             */
            type: function(type) {
                return _chain.call(this, 'type', type, validators.type);
            },

            /**
             * HTTP header getter/setter.
             *
             * @example ar().header('Content-Type', 'application/json');
             * @throws TypeError
             * @param {String} name - Header name.
             * @param {String} [value] - Header value.
             * @returns {Ar|String} Chains or gets the header.
             */
            header: function(name, value) {
                data.headers = data.headers || {};
                validators.string(name);
                if (typeof value !== 'undefined') {
                    validators.string(value);
                    data.headers[name] = value;
                    return this;
                }
                return data.headers[name];
            },

            /**
             * CSRF token setter for secure requests.
             *
             * @example ar().csrfToken('your-csrf-token');
             * @throws TypeError
             * @param {String} [token] - CSRF token.
             * @returns {Ar} Chains.
             */
            csrfToken: function(token) {
                return _chain.call(this, 'csrfToken', token, validators.string);
            },

            /**
             * Authentication credentials setter.
             *
             * @example ar().auth('user', 'pass');
             * @throws TypeError
             * @param {String} user - Username.
             * @param {String} passwd - Password.
             * @returns {Ar} Chains.
             */
            auth: function(user, passwd) {
                validators.string(user);
                validators.string(passwd);
                data.auth = { user: user, passwd: passwd };
                return this;
            },

            /**
             * Timeout setter (in ms).
             *
             * @example ar().timeout(1000);
             * @throws TypeError
             * @param {Number} [ms] - Timeout in milliseconds.
             * @returns {Ar|Number} Chains or gets the timeout.
             */
            timeout: function(ms) {
                return _chain.call(this, 'timeout', ms, validators.positiveInteger);
            },

            /**
             * HTTP method getter/setter.
             *
             * @example ar().method('post');
             * @throws TypeError
             * @param {String} [method] - HTTP method.
             * @returns {Ar|String} Chains or gets the method.
             */
            method: function(method) {
                return _chain.call(this, 'method', method, validators.method);
            },

            /**
             * Query string getter/setter.
             *
             * @example ar().queryString({ user: '12' });
             * @throws TypeError
             * @param {Object|String} [params] - Query parameters.
             * @returns {Ar|Object} Chains or gets the params.
             */
            queryString: function(params) {
                return _chain.call(this, 'queryString', params, validators.queryString);
            },

            /**
             * Request data getter/setter.
             *
             * @example ar().data({ user: '12' });
             * @throws TypeError
             * @param {Object} [params] - Data to send.
             * @returns {Ar|Object} Chains or gets the data.
             */
            data: function(params) {
                return _chain.call(this, 'data', params, validators.plainObject);
            },

            /**
             * Request body getter/setter.
             *
             * @example ar().body(new FormData());
             * @throws TypeError
             * @param {String|Object|Array|Boolean|Number|FormData} [content] - Body content.
             * @returns {Ar|*} Chains or gets the body.
             */
            body: function(content) {
                return _chain.call(this, 'body', content, null, function(content) {
                    if (typeof content === 'object' && !(content instanceof FormData)) {
                        try {
                            content = JSON.stringify(content);
                            this.header('Content-Type', 'application/json');
                        } catch (e) {
                            throw new TypeError('Unable to stringify body content: ' + e.message);
                        }
                    } else {
                        content = content + ''; // Cast to string
                    }
                    return content;
                });
            },

            /**
             * Container selector getter/setter for HTML responses.
             *
             * @example ar().into('div > .container');
             * @throws TypeError
             * @param {String|HTMLElement} [selector] - CSS selector or element.
             * @returns {Ar|Array} Chains or gets the elements.
             */
            into: function(selector) {
                return _chain.call(this, 'into', selector, validators.selector, function(selector) {
                    if (typeof selector === 'string') {
                        return document.querySelectorAll(selector);
                    }
                    if (selector instanceof HTMLElement) {
                        return [selector];
                    }
                });
            },

            /**
             * JSONP padding name getter/setter.
             *
             * @example ar().jsonPaddingName('callback');
             * @throws TypeError
             * @param {String} [paramName] - Callback parameter name.
             * @returns {Ar|String} Chains or gets the padding name.
             */
            jsonPaddingName: function(paramName) {
                return _chain.call(this, 'jsonPaddingName', paramName, validators.string);
            },

            /**
             * JSONP padding value getter/setter.
             *
             * @example ar().jsonPadding('someFunction');
             * @throws TypeError
             * @param {String} [padding] - Callback function name.
             * @returns {Ar|String} Chains or gets the padding value.
             */
            jsonPadding: function(padding) {
                return _chain.call(this, 'jsonPadding', padding, validators.func);
            },

            /**
             * Attach an event handler.
             *
             * @example ar().on('success', res => console.log('Success:', res));
             * @param {String} name - Event name (e.g., 'success', 'error', 'timeout').
             * @param {Function} cb - Callback function.
             * @returns {Ar} Chains.
             */
            on: function(name, cb) {
                if (typeof cb === 'function') {
                    events[name] = events[name] || [];
                    events[name].push(cb);
                }
                return this;
            },

            /**
             * Remove all handlers for an event.
             *
             * @example ar().off('success');
             * @param {String} name - Event name.
             * @returns {Ar} Chains.
             */
            off: function(name) {
                events[name] = [];
                return this;
            },

            /**
             * Trigger an event.
             *
             * @example ar().trigger('error', new Error('Failed'));
             * @param {String} name - Event name.
             * @param {*} data - Event data.
             * @returns {Ar} Chains.
             */
            trigger: function(name, data) {
                var self = this;
                var eventCalls = function(name, data) {
                    if (events[name] instanceof Array) {
                        events[name].forEach(function(event) {
                            event.call(self, data);
                        });
                    }
                };
                if (typeof name !== 'undefined') {
                    name = name + '';
                    var statusPattern = /^([0-9])([0-9x])([0-9x])$/i;
                    var triggerStatus = name.match(statusPattern);
                    if (triggerStatus && triggerStatus.length > 3) {
                        Object.keys(events).forEach(function(eventName) {
                            var listenerStatus = eventName.match(statusPattern);
                            if (
                                listenerStatus &&
                                listenerStatus.length > 3 &&
                                triggerStatus[1] === listenerStatus[1] &&
                                (listenerStatus[2] === 'x' || triggerStatus[2] === listenerStatus[2]) &&
                                (listenerStatus[3] === 'x' || triggerStatus[3] === listenerStatus[3])
                            ) {
                                eventCalls(eventName, data);
                            }
                        });
                    } else if (events[name]) {
                        eventCalls(name, data);
                    }
                }
                return this;
            },

            /**
             * Execute the request and return a Promise.
             *
             * @example ar().url('data.json').on('success', res => console.log(res)).go();
             * @returns {Promise} Resolves with response data or rejects with an error.
             */
            go: function() {
                var type = data.type || (data.into ? 'html' : 'json');
                var url = _buildQuery();
                return arGo[type].call(this, url);
            },

            /**
             * Execute the request using the Fetch API.
             *
             * @example ar().url('data.json').fetch().then(res => console.log(res));
             * @returns {Promise} Resolves with response data or rejects with an error.
             */
            fetch: function() {
                var type = data.type || (data.into ? 'html' : 'json');
                var url = _buildQuery();
                return arGo._fetch.call(this, url, type);
            }
        };

        /**
         * Communication methods for Ar.go and Ar.fetch.
         * @private
         */
        var arGo = {
            /**
             * XHR request for JSON data.
             * @param {String} url - The URL.
             * @returns {Promise} Resolves with parsed JSON or rejects with an error.
             */
            json: function(url) {
                return arGo._xhr.call(this, url, function(res) {
                    if (res) {
                        try {
                            return JSON.parse(res);
                        } catch (e) {
                            this.trigger('error', new Error('JSON parse error: ' + e.message));
                            throw e;
                        }
                    }
                    return null;
                });
            },

            /**
             * XHR request for HTML data.
             * @param {String} url - The URL.
             * @returns {Promise} Resolves with HTML string or rejects with an error.
             */
            html: function(url) {
                return arGo._xhr.call(this, url, function(res) {
                    if (data.into && data.into.length) {
                        [].forEach.call(data.into, function(elt) {
                            elt.innerHTML = res;
                        });
                    }
                    return res;
                });
            },

            /**
             * XHR request implementation.
             * @param {String} url - The URL.
             * @param {Function} processRes - Process response before resolving.
             * @returns {Promise} Resolves with processed response or rejects with an error.
             */
            _xhr: function(url, processRes) {
                var self = this;
                return new Promise(function(resolve, reject) {
                    var method = data.method || 'get';
                    var async = data.sync !== true;
                    var request = new XMLHttpRequest();
                    var body = data.body;
                    var timeout = data.timeout;
                    var timeoutId;

                    if (data.csrfToken && ['post', 'put', 'delete', 'patch'].indexOf(method.toLowerCase()) > -1) {
                        self.header('X-CSRF-Token', data.csrfToken);
                    }

                    if (_dataInBody() && data.data) {
                        if (!self.header('Content-Type')) {
                            self.header('Content-Type', 'application/x-www-form-urlencoded;charset=utf-8');
                        }
                        var contentType = self.header('Content-Type');
                        if (contentType.indexOf('json') > -1) {
                            body = JSON.stringify(data.data);
                        } else {
                            body = Object.keys(data.data)
                                .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data.data[key]))
                                .join('&');
                        }
                    }

                    var openParams = [method, url, async];
                    if (data.auth) {
                        openParams.push(data.auth.user, data.auth.passwd);
                    }
                    request.open.apply(request, openParams);

                    for (var header in data.headers) {
                        request.setRequestHeader(header, data.headers[header]);
                    }

                    request.onprogress = function(e) {
                        if (e.lengthComputable) {
                            self.trigger('progress', e.loaded / e.total);
                        }
                    };

                    request.onload = function() {
                        if (timeoutId) {
                            clearTimeout(timeoutId);
                        }
                        var response = request.responseText;
                        if (request.status >= 200 && request.status < 300) {
                            var processed = typeof processRes === 'function' ? processRes.call(self, response) : response;
                            self.trigger('success', processed);
                            resolve(processed);
                        } else {
                            var err = new Error(`HTTP ${request.status}: ${request.statusText}`);
                            err.status = request.status;
                            self.trigger('error', err);
                            reject(err);
                        }
                        self.trigger(request.status, response);
                        self.trigger('end', response);
                    };

                    request.onerror = function() {
                        if (timeoutId) {
                            clearTimeout(timeoutId);
                        }
                        var err = new Error('Network Error');
                        self.trigger('error', err);
                        reject(err);
                    };

                    if (timeout) {
                        timeoutId = setTimeout(function() {
                            var err = new Error('Request timed out after ' + timeout + 'ms');
                            err.type = 'timeout';
                            err.expiredAfter = timeout;
                            self.trigger('timeout', err);
                            request.abort();
                            reject(err);
                        }, timeout);
                    }

                    request.send(body);
                });
            },

            /**
             * Fetch API implementation.
             * @param {String} url - The URL.
             * @param {String} type - Request type (json, html).
             * @returns {Promise} Resolves with response data or rejects with an error.
             */
            _fetch: function(url, type) {
                var self = this;
                return new Promise(function(resolve, reject) {
                    var method = data.method || 'get';
                    var body = data.body;
                    var headers = new Headers(data.headers || {});

                    if (data.csrfToken && ['post', 'put', 'delete', 'patch'].indexOf(method.toLowerCase()) > -1) {
                        headers.set('X-CSRF-Token', data.csrfToken);
                    }

                    if (_dataInBody() && data.data) {
                        if (!headers.get('Content-Type')) {
                            headers.set('Content-Type', 'application/x-www-form-urlencoded;charset=utf-8');
                        }
                        if (headers.get('Content-Type').includes('json')) {
                            body = JSON.stringify(data.data);
                        } else {
                            body = Object.keys(data.data)
                                .map(key => encodeURIComponent(key) + '=' + encodeURIComponent(data.data[key]))
                                .join('&');
                        }
                    }

                    var options = {
                        method: method,
                        headers: headers,
                        credentials: data.auth ? 'include' : 'same-origin',
                        body: body
                    };

                    if (data.sync === true) {
                        options.mode = 'no-cors';
                    }

                    fetch(url, options)
                        .then(function(response) {
                            if (response.ok) {
                                if (type === 'json') {
                                    return response.json().then(function(json) {
                                        self.trigger('success', json);
                                        resolve(json);
                                    });
                                } else if (type === 'html') {
                                    return response.text().then(function(text) {
                                        if (data.into && data.into.length) {
                                            [].forEach.call(data.into, function(elt) {
                                                elt.innerHTML = text;
                                            });
                                        }
                                        self.trigger('success', text);
                                        resolve(text);
                                    });
                                } else {
                                    return response.text().then(function(text) {
                                        self.trigger('success', text);
                                        resolve(text);
                                    });
                                }
                            } else {
                                var err = new Error(`HTTP ${response.status}: ${response.statusText}`);
                                err.status = response.status;
                                self.trigger('error', err);
                                reject(err);
                            }
                        })
                        .catch(function(err) {
                            self.trigger('error', err);
                            reject(err);
                        })
                        .finally(function() {
                            self.trigger('end');
                        });
                });
            },

            /**
             * JSONP request.
             * @param {String} url - The URL.
             * @returns {Promise} Resolves with JSONP response or rejects with an error.
             */
            jsonp: function(url) {
                var self = this;
                return new Promise(function(resolve, reject) {
                    var head = document.querySelector('head');
                    var async = data.sync !== true;
                    var jsonPaddingName = data.jsonPaddingName || 'callback';
                    var jsonPadding = data.jsonPadding || ('_padd' + Date.now() + Math.floor(Math.random() * 10000));
                    var paddingQuery = {};

                    if (window[jsonPadding]) {
                        var err = new Error('Padding ' + jsonPadding + ' already exists.');
                        self.trigger('error', err);
                        reject(err);
                        return;
                    }

                    window[jsonPadding] = function(response) {
                        self.trigger('success', response);
                        head.removeChild(script);
                        window[jsonPadding] = undefined;
                        resolve(response);
                    };

                    paddingQuery[jsonPaddingName] = jsonPadding;
                    url = appendQueryString(url, paddingQuery);

                    var script = document.createElement('script');
                    script.async = async;
                    script.src = url;
                    script.onerror = function() {
                        var err = new Error('JSONP script load error');
                        self.trigger('error', err);
                        head.removeChild(script);
                        window[jsonPadding] = undefined;
                        reject(err);
                    };
                    head.appendChild(script);
                });
            },

            /**
             * Script loading.
             * @param {String} url - The URL.
             * @returns {Promise} Resolves on load or rejects on error.
             */
            script: function(url) {
                var self = this;
                return new Promise(function(resolve, reject) {
                    var head = document.querySelector('head') || document.querySelector('body');
                    var async = data.sync !== true;

                    if (!head) {
                        var err = new Error('No head or body tag found for script loading.');
                        self.trigger('error', err);
                        reject(err);
                        return;
                    }

                    var script = document.createElement('script');
                    script.async = async;
                    script.src = url;
                    script.onload = function() {
                        self.trigger('success', {});
                        resolve({});
                    };
                    script.onerror = function() {
                        self.trigger('error', new Error('Script load error'));
                        head.removeChild(script);
                        reject(new Error('Script load error'));
                    };
                    head.appendChild(script);
                });
            }
        };

        /**
         * Helper for getter/setter chaining.
         * @private
         * @param {String} name - Property name.
         * @param {*} [value] - Property value.
         * @param {Function} [validator] - Validation function.
         * @param {Function} [update] - Update function.
         * @returns {Ar|*} Chains or gets the value.
         */
        var _chain = function(name, value, validator, update) {
            if (typeof value !== 'undefined') {
                if (typeof validator === 'function') {
                    try {
                        value = validator.call(validators, value);
                    } catch (e) {
                        throw new TypeError('Failed to set ' + name + ': ' + e.message);
                    }
                }
                data[name] = typeof update === 'function' ? update.call(this, value) : value;
                return this;
            }
            return data[name] === 'undefined' ? null : data[name];
        };

        /**
         * Check if data should be sent in the body.
         * @private
         * @returns {Boolean} True if data goes in the body.
         */
        var _dataInBody = function() {
            return ['delete', 'patch', 'post', 'put'].indexOf((data.method || 'get').toLowerCase()) > -1;
        };

        /**
         * Build the request URL.
         * @private
         * @returns {String} The URL with query string.
         */
        var _buildQuery = function() {
            var url = data.url;
            var cache = typeof data.cache !== 'undefined' ? !!data.cache : true;
            var queryString = data.queryString || '';

            if (cache === false) {
                queryString += '&ajabuster=' + Date.now();
            }

            url = appendQueryString(url, queryString);

            if (data.data && !_dataInBody()) {
                url = appendQueryString(url, data.data);
            }
            return url;
        };

        return Ar;
    };

    /**
     * Validation rules for getters/setters.
     */
    var validators = {
        bool: function(value) {
            return !!value;
        },
        string: function(string) {
            if (typeof string !== 'string') {
                throw new TypeError('A string is expected, but ' + string + ' [' + typeof string + '] given');
            }
            return string;
        },
        positiveInteger: function(integer) {
            if (parseInt(integer) !== integer || integer <= 0) {
                throw new TypeError('An integer > 0 is expected, but ' + integer + ' [' + typeof integer + '] given');
            }
            return integer;
        },
        plainObject: function(object) {
            if (typeof object !== 'object' || object.constructor !== Object) {
                throw new TypeError('An object is expected, but ' + object + ' [' + typeof object + '] given');
            }
            return object;
        },
        type: function(type) {
            type = this.string(type);
            if (types.indexOf(type.toLowerCase()) < 0) {
                throw new TypeError('A type in [' + types.join(', ') + '] is expected, but ' + type + ' given');
            }
            return type.toLowerCase();
        },
        method: function(method) {
            method = this.string(method);
            if (methods.indexOf(method.toLowerCase()) < 0) {
                throw new TypeError('A method in [' + methods.join(', ') + '] is expected, but ' + method + ' given');
            }
            return method.toLowerCase();
        },
        queryString: function(params) {
            var object = {};
            if (typeof params === 'string') {
                params.replace('?', '').split('&').forEach(function(kv) {
                    var pair = kv.split('=');
                    if (pair.length === 2) {
                        object[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
                    }
                });
            } else {
                object = params;
            }
            return this.plainObject(object);
        },
        selector: function(selector) {
            if (typeof selector !== 'string' && !(selector instanceof HTMLElement)) {
                throw new TypeError('A selector or HTMLElement is expected, but ' + selector + ' [' + typeof selector + '] given');
            }
            return selector;
        },
        func: function(functionName) {
            functionName = this.string(functionName);
            if (!/^([a-zA-Z_])([a-zA-Z0-9_\-])+$/.test(functionName)) {
                throw new TypeError('A valid function name is expected, but ' + functionName + ' [' + typeof functionName + '] given');
            }
            return functionName;
        }
    };

    /**
     * Append query string parameters to URL.
     * @private
     * @param {String} url - The base URL.
     * @param {Object|String} params - Query parameters.
     * @returns {String} The updated URL.
     */
    var appendQueryString = function(url, params) {
        url = url || '';
        if (params) {
            if (url.indexOf('?') === -1) {
                url += '?';
            }
            if (typeof params === 'string') {
                url += params;
            } else if (typeof params === 'object') {
                for (var key in params) {
                    if (!/[?&]$/.test(url)) {
                        url += '&';
                    }
                    url += encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
                }
            }
        }
        return url;
    };

    // AMD, CommonJS, or globals
    if (typeof window.define === 'function' && window.define.amd) {
        window.define([], function() {
            return ar;
        });
    } else if (typeof exports === 'object') {
        module.exports = ar;
    } else {
        window.ar = window.ar || ar;
    }

    // EOF
})();