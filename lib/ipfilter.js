/*!
 * Dwolla - IP Filter
 * Copyright(c) 2012 Dwolla Inc.
 * MIT Licensed
 */


/**
 * Module dependencies.
 */
var _ = require('lodash')
  , iputil = require('ip')
  , Netmask = require('netmask').Netmask;

/**
 * node-ipfilter:
 *
 * IP Filtering middleware; 
 *
 * Examples:
 *
 *      var ipfilter = require('ipfilter'),
 *          ips = ['127.0.0.1'];
 *
 *      app.use(ipfilter(ips));
 *
 * Options:
 *
 *  - `mode` whether to deny or grant access to the IPs provided. Defaults to 'deny'.
 *  - `log` console log actions. Defaults to true.
 *  - `errorCode` the HTTP status code to use when denying access. Defaults to 401.
 *  - `errorMessage` the error message to use when denying access. Defaults to 'Unauthorized'.
 *  - `allowPrivateIPs` whether to grant access to any IP using the private IP address space unless explicitly denied. Defaults to false.
 *  - 'cidr' whether ips are ips with a submnet mask.  Defaults to 'false'.
 *
 * @param [Array] IP addresses
 * @param {Object} options
 * @api public
 */
 module.exports = function ipfilter(ips, opts) {
  ips = ips || false;

  var settings = _.defaults( opts || {}, {
    mode: 'deny'
    , log: true
    , errorCode: 401
    , errorMessage: 'Unauthorized'
    , allowPrivateIPs: false
    , cidr: false
    , ranges: false
  });

  var getClientIp = function(req) {
    console.log("DIAGNOSTICS: ","Forwarded: ",req.headers['x-forwarded-for']," REQ IP: ",req.connection.remoteAddress);

    var ipAddress;

    var forwardedIpsStr = req.headers['x-forwarded-for'];

    if (forwardedIpsStr) {
      var forwardedIps = forwardedIpsStr.split(',');
      ipAddress = forwardedIps[0];
    }

    if (!ipAddress) {
      ipAddress = req.connection.remoteAddress;
    }

    if(ipAddress.indexOf(':') !== -1){
      ipAddress = ipAddress.split(':')[0];
    }

    console.log("Current IP: ",ipAddress);

    return ipAddress;
  };

  var matchClientIp = function(ip){
    var mode = settings.mode.toLowerCase()
      , allowedIp = false
      , notBannedIp = false
      , isPrivateIpOkay = false; // Normalize mode

    if(settings.cidr){
      for(var i = 0; i < ips.length; i++){

        var block = new Netmask(ips[i]);

        if(block.contains(ip)){
          allowedIp = (mode == 'allow');
          break;
        }else{
          notBannedIp = (mode == 'deny');
          isPrivateIpOkay = settings.allowPrivateIPs && iputil.isPrivate(ip);
        }
      }
    }else if(settings.ranges){
      var filteredSet = _.filter(ips,function(ipSet){
        if(ipSet.length > 1){
          var startIp = iputil.toLong(ipSet[0]);
          var endIp = iputil.toLong(ipSet[1]);
          var longIp = iputil.toLong(ip);
          return  longIp >= startIp && longIp <= endIp;
        }else{
          return ip == ipSet[0];
        }
      });

      allowedIp = (mode == 'allow' && filteredSet.length > 0);
      notBannedIp = (mode == 'deny' && filteredSet.length === 0);
      isPrivateIpOkay = settings.allowPrivateIPs && iputil.isPrivate(ip) && !(mode == 'deny' && filteredSet.length > 0);
    }else{
      allowedIp = (mode == 'allow' && ips.indexOf(ip) !== -1);
      notBannedIp = (mode == 'deny' && ips.indexOf(ip) === -1);
      isPrivateIpOkay = settings.allowPrivateIPs && iputil.isPrivate(ip) && !(mode == 'deny' && ips.indexOf(ip) !== -1);
    }

    return allowedIp || notBannedIp || isPrivateIpOkay;
  };
  
  return function(req, res, next) {
    var ip = getClientIp(req);
    // If no IPs were specified, skip
    // this middleware
    if(!ips || !ips.length) { return next(); }

    if(matchClientIp(ip)) {
      // Grant access
      if(settings.log) {
        console.log('Access granted to IP address: ' + ip);
      }

      return next();
    }

    // Deny access
    if(settings.log) {
      console.log('Access denied to IP address: ' + ip);
    }

    res.statusCode = settings.errorCode;
    return res.end(settings.errorMessage);
  };
};