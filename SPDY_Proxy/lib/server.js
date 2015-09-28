var spdy = require('spdy');
var path = require('path');
var util = require('util');
var net = require('net');
var url = require('url');
var fs = require('fs');
var http = require('http');

http.globalAgent.maxSockets = 6

/**
 * Main SPDY proxy object
 */
var SPDYProxy = function(options) {
  var self = this;

  this.dbgmsg = options.dbgmsg;
  this.enablePush = options.push;
  this.enableReprio = options.reprio;
  this.onlyfingerprint = options.onlyfingerprint;

  this.push_streams = {}; // A place to store push streams

  this.startTime = new Date().getTime();
  this.pageStartTime = this.startTime;
  
  this.useCompression = false;
  //this.useSquid = true;
  this.useSquid = options.squid;

  loadFingerprints();
  loadBlocklist();

  if (this.useSquid) {
    console.log('Squid will be used');
  }

  this.setAuthHandler = function(handler) {
    self._authHandler = handler;
    console.log('AuthHandler', handler,
        'will be used.');
  }

  this.setLogHandler = function(handler) {
    self._logHandler = handler;
    console.log('Requests will be logged into file',
        handler._filename);
  }

  //The function of listing obj's contents in console
  var listContents = function(fingerprint) {
    for (var url in fingerprint) {
      console.log(url + " resources:" + fingerprint[url]['resources'].length + ' patterns:' + Object.keys(fingerprint[url]['pattern2match_set']).length);
    }
  }

  function loadFingerprints() {
    self.sites = {};
    if (options.fingerprintFile) {
      fs.readFile(options.fingerprintFile, 'utf8', function(err, data) {
        if (err) {
          console.log('Error: ' + err);
          return;
        }
    
        self.sites = JSON.parse(data);
        if (options.verbose) {
          console.log("Fingerprints loaded");
        }
        listContents(self.sites);
      });
    }
  }

  function loadBlocklist() {
    self.blocklist = {};
    if (options.blockListFile) {
      fs.readFile(options.blockListFile, 'utf8', function(err, data) {
        if (err) {
          console.log('Error: ' + err);
          return;
        }
        self.blocklist = JSON.parse(data);
        if (options.verbose) {
          console.log("blocklist loaded");
        }
        for (var url in self.blocklist) {
          self.blocklist[url] = self.blocklist[url].map(function(rx) {
            if (rx.slice(0,10) == 'http\\:\\/\\/') {
              rx = rx.slice(10);
            }
            else if (rx.slice(0,11) == 'https\\:\\/\\/') {
               rx = rx.slice(11);
            }
            else {
              if (self.dbgmsg) {
                console.log('regex not trimmed:' + rx);
              }
            }
            return rx;
          });
          self.blocklist[url] = self.blocklist[url].map(function(rx) { return RegExp(rx) });
        }
      });
    }
  }

  function convertRegexes(fingerprint) {
    for (var url in fingerprint){
      pattern2match_set = fingerprint[url]['pattern2match_set'];
      new_pattern2match_set = {};
      console.log('fingerprint[url][pattern2match_set]:' + Object.keys(fingerprint[url]['pattern2match_set']));
      for (var pattern in pattern2match_set) {
        new_pattern2match_set[new RegExp(pattern)] = pattern2match_set[pattern];
      }
      fingerprint[url]['pattern2match_set'] = new_pattern2match_set;
      console.log('fingerprint[url][pattern2match_set]:' + Object.keys(fingerprint[url]['pattern2match_set']));
    }
  }

  function logRequest(req) {
    console.log(req.method + ' ' + req.url);
    for ( var i in req.headers)
      console.log(' > ' + i + ': ' + req.headers[i]);
    console.log();
  }

  function synReply(socket, code, reason, headers, cb) {
    try {
      // SPDY socket
      if (socket._lock) {
        socket._lock(function() {
          var socket = this;
          this._spdyState.framer.replyFrame(this._spdyState.id, code, reason, headers, function(err,
              frame) {
            socket.connection.write(frame);
            socket._unlock();
            cb.call();
          });
        });

        /*socket.connection.write(this._spdyState.framer.rstFrame(this._spdyState.id, 3));
        socket._unlock();
        cb.call();*/

        // Chrome used raw SSL instead of SPDY when issuing CONNECT for
        // WebSockets. Hence, to support WS we must fallback to regular
        // HTTPS tunelling:
        // https://github.com/igrigorik/node-spdyproxy/issues/26
      } else {
        var statusLine = 'HTTP/1.1 ' + code + ' ' + reason + '\r\n';
        var headerLines = '';
        for (key in headers) {
          headerLines += key + ': ' + headers[key] + '\r\n';
        }
        socket.write(statusLine + headerLines + '\r\n', 'UTF-8', cb);
      }
    } catch (error) {
      cb.call();
    }
  }

  /**
   * Read and strip off SPDY proxy configuration parameters 
   * 
   * @param path    [String] Original path
   * @returns       [String] Path stripped off parameters for SPDY proxy configuration parameters
   */
  function readParameters(path) {
    // Obtain proxy setting parameters from url
    if (path.split('?').length > 1) {
      var _path = path.split('?')[0];
      var _params = path.split('?')[1].split('&');
      var first = true;
      for ( var i = 0; i < _params.length; i++) {
        var key = _params[i].split('=')[0];
        var value = _params[i].split('=')[1];
        
        // Enable/Disable proxy's blocking resources
        if (key == 'spdy-proxy_set-blocking') {
          if (parseInt(value) == 1)
            self.blockResources = true;
          else
            self.blockResources = false;
          console.log("SPDY Proxy\tBlocking low-util resources set to: "
              + self.blockResources);
        }
        // Regular HTTP parameters
        else {
          if (first) {
            _path += '?' + key + '=' + value;
            first = false;
          } else
            _path += '&' + key + '=' + value;
        }
      }
      return _path;
    } else
      return path;
  }

  /**
   * Callback function of cache GETs for normal resources 
   * 
   * @param cache_entry:    [Object] Cache entry for the request resource. Set to false if cache misses.
   * @param params:         [Object] Parameters for callback function.
   *    @param params.req:  [Object] HTTP request object for the original resource
   *    @param params.res:  [Object] HTTP response object for the original resource
   */
  var rres304count=0;
  function cache_callback(cache_entry, params) {
    var req = params.req;
    var res = params.res;
    var path = params.path;
    
    // Forwarding request
    var host = req.headers.host.split(':')[0];
    
    // host = ads.pubmatic.com  path = /AdServer/js/universalpixel.js
    var requestOptions = {
      host : host,
      port : req.headers.host.split(':')[1] || 80,
      path : path,
      method : req.method,
      headers : req.headers
    };

    if (self.useSquid == true) {
      requestOptions['host'] = 'localhost';
      requestOptions['port'] = 3128;
      //requestOptions['path'] = path;
      //console.log('cache_callback: path:'+ path + 'join:http://' + host + path);
      requestOptions['path'] = 'http://' + host + path;
    }

    var rreq = http.request(requestOptions, function(rres) {
      rres.headers['proxy-agent'] = 'SPDY Proxy ' + options.version;

      var data = new Buffer(0);

      //respones
      res.writeHead(rres.statusCode, '', rres.headers); // write out headers to handle redirects
      
      /*console.log('req.headers:');
      for ( var i in req.headers) {
        console.log(' > '+ i + ': ' + req.headers[i]);
      }

      console.log('res.headers:');
      for ( var i in res.headers) {
        console.log(' > ' + i + ': ' + res.headers[i]);
      }

      console.log('rreq.headers:');
      for ( var i in rreq.headers) {
        console.log(' > ' + i + ': ' + rreq.headers[i]);
      }

      console.log('rres.headers:');
      for ( var i in rres.headers) {
        console.log(' > ' + i + ': ' + rres.headers[i]);
      }*/

      rres.pipe(res);
      res.pipe(rres); // Res could not write, but it could close connection

      if (rres.statusCode != 200 && rres.statusCode != "200")
        return;
    });

    if (self.dbgmsg) {
      console.log((new Date().getTime()) + "\tRequest Sent\t"
          + requestOptions.host + requestOptions.path);
    }

    rreq.on('error', function(e) {
      console.log("Client error: " + e.message);
      res.writeHead(502, 'Proxy fetch failed');
      res.end();
    });

    // The fowared request to the real webserver is actually sent out.
    req.pipe(rreq);

    // Just in case if socket will be shutdown before http.request will connect
    // to the server.
    res.on('close', function() {
      rreq.abort();
      console.log("res.on rreq.abort error");
    });

    if (self.enablePush) {
      var item = host + path;
      if (path.charAt(path.length - 1) == '/' || /\.html/.test(path) || /\.htm/.test(path)) {
        if (self.sites[item] != null || self.sites['http://' + item] != null) {
          if (self.sites['http://' + item] != null) {
            item = 'http://' + item;
          }
          if (self.dbgmsg) {
            console.log("Fingerprint Located " + item);
          }
          initiatePushStreams(req, res, item);
        }
      }
      startPushing(req, res);
    }
  }
  
  function readCurrentUrl() {
    fs.readFile('current_url.txt', 'utf8', function(err, data) {
      if (err) {
        console.log('Error: ' + err);
        return;
      }
      // remove whitespace
      self.cur_url = data.toString().replace(/(^\s+|\s+$)/g,'');
      //if (self.dbgmsg) {
      console.log("connect recieved, current url is:" + self.cur_url);
      //}
    });
  }

  /**
   * Handles HTTP request
   * 
   * @param req:    [Object] HTTP request object for the original resource
   * @param res:    [Object] HTTP response object for the original resource
   */
  function handlePlain(req, res) {
    // Forwarding request
    var path = req.headers.path || url.parse(req.url).path;
    var host = req.headers.host.split(':')[0];

    var item = host + path;
    
      cache_callback(false, {
        "req" : req,
        "res" : res,
        "path" : path
      });
  }
  
  // req/res is reponse for the main html. item is the url of the main html
  function initiatePushStreams(req, res, item) {
    try {
      req.setMaxListeners(200);

      var sites = self.sites;
      var push_streams = self.push_streams;

      var path = req.headers.path || url.parse(req.url).path;

      // Initiate push streams
      var _length = sites[item].resources.length;
      for ( var i = 0; i < _length; i++) {

        var select_type = sites[item].resources[i].select_type;
        if (select_type != 'push') { // only pushing here
          continue
        }

        var res_url_full = sites[item].resources[i].url;
        var res_path = sites[item].resources[i].path;
        var res_host = sites[item].resources[i].host;
        var res_type = sites[item].resources[i].type;
        var res_encoding = sites[item].resources[i].encoding;

        var request_headers = undefined;
        if ('request_headers' in sites[item].resources[i]) {
          request_headers = sites[item].resources[i].request_headers;
        }

        var response_headers = undefined;
        if ('response_headers' in sites[item].resources[i]) {
          response_headers = sites[item].resources[i].response_headers;
        }

        var content_encoding = undefined;
        if (self.useCompression) {
          if ('response_headers' in sites[item].resources[i]) {
            if ('content-encoding' in sites[item].resources[i].response_headers) {
              // ask for gziped push resources
              //compression
              var content_encoding = sites[item].resources[i].response_headers['content-encoding'];
            }
          }
        }

        var res_url = res_host + res_path;

        // If push stream already in use, abort
        if (self.push_streams[res_url] != null) {
          console.log("ERROR".red, ": Push stream for " + res_url
              + "already in use.");
          continue;
        }

        self.push_streams[res_url] = {
            "status" : "init",
            "host" : res_host,
            "path" : res_path,
            "stream" : null,
            "response": res,
            "encoding" : res_encoding,
            "buffer" : "",
            "type" : res_type,
            "data" : "",
            "request_headers" : request_headers,
            "content_encoding" : content_encoding
        }


        /*var header_vals = response_headers;
        header_vals['content-type'] = res_type;
        header_vals['served-by'] = 'server push';
        header_vals['cache-control'] = 'max-age=600';
        header_vals['mike_url'] = res_url;*/
        var header_vals = {
            'content-type' : res_type,
            'served-by' : 'server push',
            'cache-control' : 'max-age=600',
            'mike_url' : res_url
        };

        if (content_encoding !== undefined) {
          // tell client that push will be gziped
          header_vals['content-encoding'] = content_encoding;
          if ('content-length' in response_headers) {
            header_vals['content-length'] = response_headers['content-length'];
          }
        }

        res.push(res_host, res_path, res_url_full,
            header_vals,
            1, // priority
            function(err, stream) {
              if (err)
                console.log("ERROR PUSHING");

              var mike_url = stream._spdyState.headers.mike_url;

              if (self.dbgmsg) {
                console.log((new Date().getTime()) + "\tPush Stream Initiated\t" + mike_url);
              }

              // If the resource is already fetched by the time this client push ack comes back
              if (self.push_streams[mike_url].status == "end") {
                //console.log("Push stream was already fetched" + mike_url);
                stream.write(self.push_streams[mike_url].buffer, self.push_streams[mike_url].encoding);
                stream.end();
                delete self.push_streams[mike_url];
              } else
                self.push_streams[mike_url].stream = stream;
            }
          );
        }
    }
    
    catch (err) {
      console.log("ERROR place 1");
      dumpError(err);
    } 
  }
  
  function startPushing(req, res, page_url) {
    try{
      var sites = self.sites;
      var push_streams = self.push_streams;

      var path = req.headers.path || url.parse(req.url).path;
    
      for (var i in self.push_streams) {
        if (self.push_streams[i].response == res) {
          var params = {
              "req" : req,
              "res" : res,
              "res_url" : i,
          }
          
          if (self.push_streams[i].status != "init")
            continue;
          
          self.push_streams[i].status = "pushing";
          
          pushed_cache_callback(false, params);
        }
      }
    } catch (err) {
      console.log("ERROR place 4");
      dumpError(err);
    } 
  }

  /**
   * Callback function of cache GETs for pushed resources
   * 
   * @param cache_entry:    [Object] Cache entry for the request resource. Set to false if cache misses.
   * @param params:         [Object] Parameters for callback function.
   *    @param params.req:          [Object] HTTP request object for the main HTML
   *    @param params.res:          [Object] HTTP response object for the main HTML
   *    @param params.res_url:      [String] Url for the pushed resource
   */
  function pushed_cache_callback(cache_entry, params) {
    try{
    var req = params.req;
    var res = params.res;
    var res_url = params.res_url;
    
    var push_streams = self.push_streams;

    var item = res_url;
    
    var stream_entry = self.push_streams[res_url];
    var res_host = stream_entry.host;
    var res_path = stream_entry.path;
    var res_type = stream_entry.type;
    var res_encoding = stream_entry.encoding;
    var request_headers = stream_entry.request_headers;
    var content_encoding = stream_entry.content_encoding;

    // Send request via HTTP GET    
    var header_vals = {
      //'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.71 Safari/537.36'
      'User-Agent' : 'Mozilla/5.0 (Linux; Android 4.1.2; GT-N7000 Build/JZO54K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.141 Mobile Safari/537.36'
    };

    if (request_headers !== undefined) {
        for (var name in request_headers) {
          header_vals[name] = request_headers[name];
        }
        if (content_encoding !== undefined) {
          // push reaource which was gziped in previous load, ask webserver for gziped copy this time (to pass back to client)
          header_vals['accept-encoding'] = 'gzip,deflate,sdch';
        }
    }

    var resRequestOptions = {
      hostname : res_host,
      port : 80,
      path : res_path,
      method : 'GET',
      headers : header_vals
    };
      resRequestOptions['headers']['stream_name_url'] = res_host + res_path;

    if (self.useSquid == true) {
      resRequestOptions['hostname'] = 'localhost';
      resRequestOptions['port'] = 3128;
      //resRequestOptions['path'] = res_path;
      resRequestOptions['path'] = 'http://' + res_host + res_path;
    }

    // the proxy->server request for a push resource
    var res_req = http.request(resRequestOptions,
      function(res_res) {

        /*
        console.log('res_req headers');
        if ('_headers' in res_res.req) {
          for ( var prop in res_res.req._headers ) {
            if ( res_res.req._headers.hasOwnProperty( prop ) ) {
              console.log('header ' + prop + ' ' +  res_res.req._headers[prop] );
            }
          }
        }
 
        console.log('res_res headers');
        if ('headers' in res_res) {
          for ( var prop in res_res.headers ) {
            if ( res_res.headers.hasOwnProperty( prop ) ) {
              console.log('header ' + prop + ' ' +  res_res.headers[prop] );
            }
          }
        }
        */

        var entry = res_res.req._headers['stream_name_url'];
        
        var old_encoding = undefined;
        if (self.push_streams[entry].content_encoding !== undefined) {
            old_encoding = self.push_streams[entry].content_encoding;
            // gzip status from last load (fingerprint)
        }

        var encoding = undefined;
        // if the server response was gziped, set prozy->client encoding to binary

        if ('headers' in res_res && 'content-encoding' in res_res.headers) {
          encoding = "binary";
          
          //console.log('content-encoding detected ' + entry + ' ' + res_res.headers['content-encoding']);
          if (old_encoding === undefined) {
            console.log('content-encoding error: compression none->enabled. ' + entry + ' ' + res_res.headers['content-encoding']);
          }
        }
        else {
          // if response is not gziped, then use the fingerprint encoding data from previous load
          encoding = self.push_streams[entry].encoding;
          if (old_encoding !== undefined) {
            console.log('content-encoding error: compression enabled->none. ' + entry);
          }
        }

        res_res.setEncoding(encoding);

        res_res.on('data', function(chunk) {
          if (chunk != null && chunk.length != 0) {
            self.push_streams[entry].buffer += chunk;
            self.push_streams[entry].data += chunk;

            // If the push stream has been setup
            if (self.push_streams[entry].stream != null) {      
              self.push_streams[entry].stream.write(self.push_streams[entry].buffer, encoding);
              self.push_streams[entry].buffer = new Buffer(0);
            }
          }
        });

        res_res.on('end', function() {
          if (self.push_streams[entry].stream != null) {
            self.push_streams[entry].stream.end();
            delete self.push_streams[entry];
          } else
            // If the push stream has not been setup
            self.push_streams[entry].status = "end";
        });
      }
    );
  
    if (self.dbgmsg) {
      console.log((new Date().getTime()) + "\tPush Request Sent\t"
        + "hostname:" + resRequestOptions.hostname + " path:" + resRequestOptions.path);
    }

    // res_req, just defined, is now sent to the webserver 
      req.pipe(res_req);

    } catch (err) {
      console.log("ERROR place 5");
      dumpError(err);
    } 
  }

  function handleSecure(req, socket) {
    var dest = req.url.split(':');

    var code = 200;
    var label = 'Connection established';
    if (self.onlyfingerprint){
      code = 404;
      label = 'Not Found Mike';
    }

    //socket.connection.write(socket._spdyState.framer.rstFrame(socket._spdyState.id, 3));
    //socket.end();

    console.log('code:' + code);
    var tunnel = net.createConnection(dest[1] || 443, dest[0], function() {
      synReply(socket, code, label, {
        'Connection' : 'keep-alive',
        'Proxy-Agent' : 'SPDY Proxy ' + options.version
      }, function() {
        tunnel.pipe(socket);
        socket.pipe(tunnel);
      });
    });

    tunnel.setNoDelay(true);

    tunnel.on('error', function(e) {
      console.log("Tunnel error: ".red + e);
      synReply(socket, 502, "Tunnel Error", {}, function() {
        socket.end();
      });
    });
  }

  function reprioritize(socket, req, res, host, path) {
    obj_url = host+path;
    if (self.dbgmsg) {console.log('reprioritize:' + obj_url);}
    if (socket._spdyState !== undefined) {
      if (self.dbgmsg) {console.log('method:' + req.method + ' URL:' + host+path + ' Priority:' + socket._spdyState.priority);}
      prio = socket._spdyState.priority;
      if (prio > 0) {
        socket._spdyState.priority = prio + 3;
      }
      if (self.dbgmsg) {console.log('Reprioritized to:' + socket._spdyState.priority);}
      if (self.enableReprio) {
        if (self.cur_url in self.sites) {
          if ('static_set' in self.sites[self.cur_url]) {
            // static resource
            if (obj_url in self.sites[self.cur_url]['static_set']) {
              if (self.dbgmsg) {console.log('resource was static, so prio stays the same');}
              return; // do nothing
            }
            // dynamic resource
            else {
              if (self.dbgmsg) {console.log('resource is dynamic!');}
              if ('pattern2match_set' in self.sites[self.cur_url]) {
                var min_prio = socket._spdyState.priority;
                // for each possible regex
                for (var regex in self.sites[self.cur_url]['pattern2match_set']) {
                  // dynamic resource matches this regex
                  if (RegExp(regex).test(obj_url, 'i')) {
                    var match_set = self.sites[self.cur_url]['pattern2match_set'][regex];
                    if (self.dbgmsg) {console.log('matched pattern:' + regex + ' set of resources for match is:' + Object.keys(match_set));}
                    // for each resource matched by that regex, find min (highest) prio of that set of resources
                    for (match_resource in match_set) {
                      if (match_resource in self.sites[self.cur_url].resource2vals) {
                        if (self.dbgmsg) {console.log('other dynamic resource:' + match_resource + ' within regex had prio:' + self.sites[self.cur_url].resource2vals[match_resource]['priority']);}
                        min_prio = Math.min(min_prio, self.sites[self.cur_url].resource2vals[match_resource]['priority']);
                        if (self.dbgmsg) {console.log('min prio currently is:' + min_prio);}
                      }
                      else {
                        if (self.dbgmsg) {console.log('other dynamic resource:' + match_resource + ' not found in fingerprint');}
                      }
                    }
                  }
                  else {
                    if (self.dbgmsg) {console.log('Failed to matched obj:' + obj_url +' pattern:' + regex);}
                  }
                }
                if (min_prio != socket._spdyState.priority) {
                  if (self.dbgmsg) {console.log('Final prio changed ' + socket._spdyState.priority + '->' + min_prio);}
                  socket._spdyState.priority = min_prio;
                  req.headers['reprio'] = 'changed to ' + min_prio;
                }
                else {
                  if (self.dbgmsg) {console.log('Prio stay the same');}
                }
              }
            } // dynamic resource
          }
        } // was in fingerprint
        else {
          if (self.dbgmsg) {console.log('self.cur_url:' + self.cur_url + 'not in fingerprint, so no prio change for:' + obj_url);}
        }
      }
    } // had prio
    else {
      if (self.dbgmsg) {console.log('socket._spdyState == undefined for:' + obj_url);}
    }
  }

  function shouldBlockNotInFingerprint(host, path) {
    if (self.cur_url in self.sites) {
      if ('http://' + host+path != self.cur_url) {
          console.log("url:" + self.cur_url + " not main html:" + 'http://' + host+path);
        if (! (host+path in self.sites[self.cur_url]['resource2vals'])) {
          console.log("url:" + self.cur_url + " blocked1:" + host+path);
          //console.log("keys: " + Object.keys(self.sites[self.cur_url]['resource2vals']));
          return true;
        }
        else {
          console.log("url:" + self.cur_url + " resource was allowed:" + host+path);
        }
      }
      else {
        console.log("url:" + self.cur_url + " main html allowed:" + host+path);
      }
    }
    else {
      console.log("current url:" + self.cur_url + " not inside fingerprint");
    }
    return false;
  }

  function shouldBlock(host, path) {
    if (self.blocklist[self.cur_url] != null) {
      var regexes = self.blocklist[self.cur_url];
      for (var i=0,len=regexes.length; i<len; i++) {
        var regex = regexes[i];
        if (regex.test(host+path)) {
          if (options.verbose) {
            console.log("url:" + self.cur_url + " blocked:" + host+path);
            return true;
          }
        }
        else {
          if (self.dbgmsg) {
            console.log("no match:" + host+path + ' ' + regex.toString());
          }
        }
      }
    }
    else {
      if (self.dbgmsg) {
        console.log("no block list entry for:" + self.cur_url);
      }
    }
    return false;
  }

  function handleRequest(req, res) {
    try {
      var socket = (req.method == 'CONNECT') ? res : res.socket;

      if (req.method == 'CONNECT') {
        readCurrentUrl();
      }

      var path = req.headers.path || url.parse(req.url).path;
      var host = req.headers.host.split(':')[0];
      //console.log('looking at:' req.connection.encrypted + ' url:' + req.url);
      var item = host + path;

      if (self.dbgmsg) {
        console.log('current url:' + self.cur_url);
      }

      reprioritize(socket, req, res, host, path);

      if (! self.useCompression) {
        if ('accept-encoding' in req.headers) {
          delete req.headers['accept-encoding'];
        }
      }

      //if (shouldBlock(host, path)) {
      // right now this is being used to block resources that were not explicitly in the har file from the orig load
      if (self.onlyfingerprint) {
        if (shouldBlockNotInFingerprint(host, path) && res.constructor.name == 'ServerResponse') {
          //console.log("url:" + self.cur_url + " writing 404 for not in har:" + host+path);
          res.writeHead(404, 'Not Found', {'Content-Type': 'text/plain'});
          res.end();
          return;
        }
      }

      // node-spdy forces chunked-encoding processing on inbound
      // requests without a content-length. However, we don't want
      // want to pass this injected header through to the destination.
      delete req.headers['transfer-encoding'];

      var dispatcher = function(req, res) {
        req.method == 'CONNECT' ? handleSecure(req, res) : handlePlain(req, res);
      }

      if (self.dbgmsg)
        logRequest(req);

      if (typeof self._logHandler == 'object') {
        self._logHandler.log(socket, req);
      }

      if (typeof self._authHandler == 'object') { // an AuthHandler is defined
        // perform basic proxy auth (over established SSL tunnel)
        // - http://www.chromium.org/spdy/spdy-authentication
        var header = req.headers['proxy-authorization'] || '', token = header
            .split(/\s+/).pop()
            || '', auth = new Buffer(token, 'base64').toString(), parts = auth
            .split(/:/), username = parts[0], password = parts[1];

        // don't pass proxy-auth headers upstream
        delete req.headers['proxy-authorization'];

        self._authHandler.authUser(username, password, function(authPassed) {
          if (authPassed)
            return dispatcher(req, res);

          synReply(socket, 407, 'Proxy Authentication Required', {
            'proxy-authenticate' : 'Basic realm="SPDY Proxy"'
          }, function() {
            socket.end();
          });
        });
      } else { // auth is not necessary, simply go ahead and dispatch to funcs
        dispatcher(req, res);
      }
    } catch (err) {
      console.log("ERROR place 3");
      dumpError(err);
    } 
  }

  try {
    spdy.server.Server.call(this, options);
  } catch (err) {
      console.log("ERROR place 2");
      dumpError(err);
  } 

  function dumpError(err) {
    if (typeof err === 'object') {
      if (err.message) {
        console.log('\nMessage: ' + err.message)
      }
      if (err.stack) {
        console.log('\nStacktrace:')
        console.log('====================')
        console.log(err.stack);
      }
    } else {
      console.log('dumpError :: argument is not an object');
    }
  }
 
  //spdy.server.Server.call(this, options);
  this.on("connect", handleRequest);
  this.on("request", handleRequest);
};

util.inherits(SPDYProxy, spdy.server.Server);

var createServer = function(options) {
  return new SPDYProxy(options);
};

exports.SPDYProxy = SPDYProxy;
exports.createServer = createServer;
