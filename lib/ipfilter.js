/*!
 * Dwolla - IP Filter
 * Copyright(c) 2012 Dwolla Inc.
 * MIT Licensed
 */
 
 // single dimension objects only
function objMergeNoDupes(d, s)
{
   for (var k in s){
      if (s.hasOwnProperty(k) && !d.hasOwnProperty(k))
         d[k] = s[k];
   }
}


/**
 * Module dependencies.
 */
 var ipv6 = require("ipv6");

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
 *  - `deny` deny access to provided IPs or not. Defaults to true.
 *  - `log` console log actions. Defaults to true.
 *  - `errorCode` the HTTP status code to use when denying access. Defaults to 401.
 *  - `errorMessage` the error message to use when denying access. Defaults to 'Unauthorized'.
 *
 * @param [Array] IP addresses
 * @param {Object} options
 * @api public
 */
module.exports = function ipfilter(ips, ops) {
   ips = ips || [];
   
   var stringToIP = function(sString)
   {
      var v6 = new ipv6.v6.Address(sString);
      
      if (v6.error){
         var v4 = new ipv6.v4.Address(sString);
         
         if (v4.error)
            throw sString + " is an invalid IPv4/6 address.";
         
         v6 = ipv6.v6.Address.fromAddress4(sString);
      }
      
      return v6;
   }
   
   var translatedIPs = [];
   ips.forEach(function(e, i){
      translatedIPs.push(stringToIP(e));
   });

   var settings = objMergeNoDupes(ops, {
      deny : true,
      log : true,
      errorCode : 401,
      errorMessage : 'Unauthorized'
   });

   var getClientIp = function(req)
   {
      var forwardedIpsStr = req.headers['x-forwarded-for'];

      var ipAddress;
      if (forwardedIpsStr) {
         var forwardedIps = forwardedIpsStr.split(',');
         ipAddress = forwardedIps[0];
      }

      if (!ipAddress)
         ipAddress = req.connection.remoteAddress;

      return stringToIP(ipAddress);
   };

   return function(req, res, next)
   {
      // If no IPs were specified, skip this middleware
      if(!ips.length)
         return next();

      var ip = getClientIp(req); // Grab the client's IP address
      var deny = settings.deny;
      
      // hacky, who compares strings for this purpose seriously?
      // always allow localhost/loopback
      if (ip.getType() == "Loopback" || ip.address == "::ffff:127.0.0.1")
         return next();

      if((!deny && ips.indexOf(ip) !== -1) || (deny && ips.indexOf(ip) === -1)) {
         // Grant access
         if(settings.log)
            console.log('Access granted to IP address: ' + ip);

         return next();
      }

      // Deny access
      if(settings.log)
         console.log('Access denied to IP address: ' + ip);
      
      res.status(settings.errorCode).send(settings.errorMessage);
      return true; // same as returning res.end();
   }
};