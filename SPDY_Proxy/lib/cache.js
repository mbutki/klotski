//The function of listing obj's contents in console

var listContents = function(obj) {
  console.log(obj + " {");
  for ( var item in obj) {
    if (typeof (obj[item]) == 'function')
      ;// console.log(" " + item + ": function()");
    else
      console.log("  " + item + ": " + obj[item]);
  }
  console.log("}");
}

var http = require('http'), path = require('path'), util = require('util'), net = require('net'), url = require('url'), fs = require('fs');
var cacheHitCount = 0;
var cachePutCount = 0;

var CacheManager = function(proxy) {
  var self = this;

  this.proxy_server = proxy;
  this.dbgmsg = false;

  this.enable_replication = false;
  this.memory_only = true;
  this.enable_cache_rules = true;
  this.memory_cache = {
    size : 0,
    entries : {},
    entry_queue : []
  };
  this.maximum_memory_cache_size = 1024000000;// 160M

  function cacheValidate(cacheEntry) {

    //console.log("headers:" + cacheEntry.options.headers);
    //console.log("cache-control:" + cacheEntry.options.headers["cache-control"]);
    //console.log("date:" + cacheEntry.options.headers["date"]);
    //console.log("expires:" + cacheEntry.options.headers["expires"]);

    var maxage = 0;
    ret = {
      "status" : null,
      "servedFrom" : "",
      "data" : cacheEntry.data,
      "encoding" : encoding,
      "entryDate" : cacheEntry.entryDate,
      "options" : cacheEntry.options
    };

    // Just in case we don't want any cache rules
    if (self.enable_cache_rules == false) {
      ret.status = "Valid";
      return ret;
    }

    if (cacheEntry.options.headers["cache-control"]) {
      if (cacheEntry.options.headers["cache-control"].indexOf("must-revalidate") != -1) {
        ret.status = "Revalidate";
        return ret;
      }
      
      var cachecontrol = new Array();
      cachecontrol = cacheEntry.options.headers["cache-control"].split(',');
      for ( var i = 0; i < cachecontrol.length; i++) {
        if (cachecontrol[i].indexOf("max-age=") != -1) {
          //console.log(cachecontrol[i]);
          maxage = Number(cachecontrol[i].split('=')[1]);
          //console.log("maxage:" + maxage);
        }
      }
    }

    // If cache entry has max-age field
    if (maxage > 0) {
      //console.log("**********HAS MAXAGE**********");
      // maxage="100000";
      // maxage='1';
      var date = new Date();
      date = cacheEntry.options.headers["date"];
      var currenttime = new Date().toGMTString();
      //console.log("entry date:" + cacheEntry.entryDate);
      var diff = Date.parse(currenttime) - Date.parse(date);
      var diff_ = new Date().getTime() - cacheEntry.entryDate;
      //console.log("current time-date:" + diff_);
      //console.log("current time-date:" + diff);
      // console.log("maxage:"+maxage);
      if (diff_ <= (maxage * 1000))
        ret.status = "Valid";
      else
        ret.status = "Revalidate";
    } else {
      var expires = cacheEntry.options.headers["expires"];
      if (expires) {
        //console.log("**********NO MAXAGE BUT HAS EXPIRES**********");
        //console.log("expires:" + expires);
        currenttime = new Date().toGMTString();
        //console.log("current time:" + currenttime);
        if (Date.parse(currenttime) <= Date.parse(expires)) {
          ret.status = "Valid";
        } else {
          ret.status = "Revalidate";
        }
      } else {
        ret.status = "Valid";
      }
    }

    //console.log(ret.status);

    return ret;
  }
  
  this.get = function(url, options, callback, params) {
    encoding = "binary";
    if (url.substr(-3) == "htm" || url.substr(-3) == "css"
        || url.substr(-4) == "html" || url.substr(-4) == "json"
        || url.substr(-2) == "js")
      encoding = "UTF-8";

    // Memory cache hit: check freshness
    if (url in self.memory_cache.entries) {
      cacheHitCount++;
      if (self.dbgmsg) {
        console.log(new Date().getTime() + "\tCache Hit from memory:\t" + url
            + "\t" + cacheHitCount);
      }
      // console.log(self.memory_cache.entries[url]);
      var ret = cacheValidate(self.memory_cache.entries[url]);
      ret.servedFrom = "memory cache"

      if (callback)
        callback(ret, params);
    }

    // Memory cache miss
    else if (self.memory_only) {
      if (self.dbgmsg) {
        console.log(new Date().getTime()
            + "\tCache Miss from memory. Database disabled:\t" + url);
      }
      if (callback)
        callback(false, params);
    }

    /*
    // Get from disk
    else {
      console.log(new Date().getTime()
          + "\tCache Miss from memory. Consulting Database:\t" + url);
      var requestOptions = {
        host : "localhost",
        port : 80,
        path : "/ds_proj/db_get.php?url=" + encodeURIComponent(url),
        method : "GET",
      };
      var get_req = http.request(requestOptions, function(res) {
        if (res.status != "200" && res.status != 200) {
          // Upon the second DB failure, return false
          console.log(new Date().getTime() + "\tCannot connect to local DB:\t"
              + url);
          return;
        }

        var res_data = "";
        res.on("data", function(chunk) {
          res_data += chunk;
        })
        res.on("end", function() {
          if (res_data == "" || res_data.charAt(0) == "<") {
            console.log(new Date().getTime() + "\tCache Miss from local Database:\t"
                + url);
            if (callback)
              callback(false, params)
          } else {
            try {
              var ret = JSON.parse(res_data);
              //console.log("STATUS" + ret.status);
              if (ret.status != "Miss") {
                console.log(new Date().getTime() + "\tCache Hit from local Database:\t"
                    + url);
                ret.status = "Valid";
                ret.data = new Buffer(ret.data, 'base64');
                ret.options.headers = JSON
                    .parse(decodeURIComponent(ret.options.headers));
                var _ret = cacheValidate(ret);
                _ret.servedFrom = "database cache," + res.req._headers.host;
                if (callback)
                  callback(_ret, params);
              }
              else {
                console.log(new Date().getTime()
                    + "\tCache Miss from local Database:\t" + url);
                if (callback)
                  callback(false, params)
              }
            } catch(err) {
              console.log(new Date().getTime() + "\tError occured\t"
                  + url);
              if (callback)
                callback(false, params);
            }
          }
        })
      });
      get_req.end();
    }
    */
  }

  this.put = function(url, data, options, callback, params) {

    if (self.memory_cache.entries[url])
      return;

    // To Lower Case
    options.headers = JSON.parse(JSON.stringify(options.headers).toLowerCase())

    // Check for no-cache headers
    if (options.headers["pragma"]
        && options.headers["pragma"].indexOf("no-cache") != -1)
      return;
    if (options.headers["cache-control"]
        && options.headers["cache-control"].indexOf("no-cache") != -1)
      return;
    if (options.headers["cache-control"] in options.headers
        && options.headers["cache-control"].indexOf("private") != -1)
      return;

    cachePutCount++;
    if (self.dbgmsg) {
      console.log(new Date().getTime() + "\tPut Cache:\t" + url + "\t"
          + data.length + "\t" + cachePutCount);
    }

    // Put memory cache
    self.memory_cache.entries[url] = {
      "data" : data,
      "entryDate" : new Date().getTime(),
      "size" : data.length,
      "options" : options
    }
    self.memory_cache.entry_queue.push(url);// memory cache input oder
    self.memory_cache.size += data.length;

    // Clear older cache if memory cache limits achieved
    while (self.memory_cache.size > self.maximum_memory_cache_size) {
      url_to_remove = self.memory_cache.entry_queue.shift();// queue.pop
      self.memory_cache.size -= self.memory_cache.entries[url_to_remove].size;
      delete self.memory_cache.entries[url_to_remove];
    }

    /*/ Update database
    if (!self.memory_only) {
      var queryData = {
        "url" : url,
        "timestamp" : (new Date().getTime()).toString(),
        "headers" : encodeURIComponent(JSON.stringify(options.headers)),
        "data" : data.toString("base64"),
      }
      var queue_data = require('querystring').stringify(queryData);
      // console.log(queue_data.substr(200));
      var length = queue_data.length;
      var contentType = 'application/x-www-form-urlencoded';
      var requestOptions = {
        host : "localhost",
        port : 80,
        path : "/ds_proj/db_local.php",
        // path : "/ds_proj/test.php",
        method : "POST",
        headers : {
          'Content-Type' : contentType,
          'Content-Length' : length
        }
      };
      var post_req = http.request(requestOptions, function(res) {
        var res_data = "";
        res.on("data", function(chunk) {
          res_data += chunk;
        })
        res.on("end", function() {
          // console.log(res_data);
        })
      });

      post_req.write(queue_data);
      post_req.end();
    }
    */
  }

  this.clear = function() {
    self.memory_cache = {
      size : 0,
      entries : {},
      entry_queue : []
    };

    var requestOptions = {
      host : "localhost",
      port : 80,
      path : "/ds_proj/db_clear.php",
      method : "GET",
    };
    var get_req = http.request(requestOptions, function(res) {
      var res_data = "";
      res.on("data", function(chunk) {
        res_data += chunk;
      })
      res.on("end", function() {
        if (self.dbgmsg) {
          console.log(new Date().getTime() + "\tDatabase cleared at\t" + res.req._headers.host);
        }
        // console.log(res_data);
      })
    });
    get_req.end();
  }
  
  this.deleteEntry = function(url) {
    if (self.memory_cache.entries[url]) {
      delete self.memory_cache.entries[url];
    }
  }
}

var initiateCacheManager = function(proxy) {
  return new CacheManager(proxy);
}

exports.CacheManager = CacheManager;
exports.initiateCacheManager = initiateCacheManager;
