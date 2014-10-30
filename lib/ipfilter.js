/*!
 * Dwolla - IP Filter
 * Copyright(c) 2012 Dwolla Inc.
 * MIT Licensed
 */


/**
 * Module dependencies.
 */


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
module.exports = function ipfilter(ips, settings) {
  ips = ips || [];

  settings = settings || {
      deny : true,
      log : true,
      errorCode : 401,
      errorMessage : 'Unauthorized'
   };
   
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

     return ipAddress;
   };
  
	return function(req, res, next)
   {
		// If no IPs were specified, skip this middleware
		if(!ips.length)
         return next();

		var ip = getClientIp(req); // Grab the client's IP address
      var deny = settings.deny;

		if((!deny && ips.indexOf(ip) !== -1) || (deny && ips.indexOf(ip) === -1)) {
			// Grant access
			if(settings.log)
				console.log('Access granted to IP address: ' + ip);

			return next();
		}

		// Deny access
		if(settings.log)
			console.log('Access denied to IP address: ' + ip);

		return res.status(settings.errorCode).send(settings.errorMessage);
	}
};