# U2F authentication library

This is a simple library to register and check signatures provided by U2F clients/devices. 
It's intended to be used in Relying Parties - websites that want to add U2F 2-factor authentication
for their users.

To use U2F, it is recommended to familiarize yourself with [FIDO Alliance Specifications](https://fidoalliance.org/specifications/download/), 
although basic usage is shown below.

## U2F Overview/properties

 * U2F provides hardware-based 2-nd factor authentication system. Public/private key infrastructure is used
   to ensure good security.
 * Provides proof of posession of hardware key, plus user presence flag.
 * Public/private key pairs are specific to website origin and 'application id'. Keys are useless if used from
   other origins.
 * Needs to be stored on server for each user: Key handle and public key (both strings).
 * Cannot be used as main authentication system because server needs to provide
   unique key handle to the user to get the signature.

## Basic usage

### User Registration Flow

```javascript
// 1. Check that the user is logged in.

// 2. (On server) generate user registration request and save it in session:
var u2f = require('u2f');

var req = u2f.request("<appId>");
session.authRequest = req;

// 3. Send req to the client and use U2F API to request registration, then send result back.
// (On client)  u2f.register([req], [], function(res) { /* send res back to server */ })

// 4. (Server) Check registration result.
var checkres = u2f.checkRegistration(session.authRequest, res);

if (checkres.successful) {
    // Registration successful, save 
    // checkres.keyHandle and checkres.publicKey to user's account in your db.
} else {
    // checkres.errorMessage will contain error text.
}
```

### User Authentication Flow
```javascript
// 1. Check that the user is logged in using password authentication (or some other way).

// 2. (On server) generate user sign request using keyHandle from user account.
var req = u2f.request("<appId>", user.keyHandle);
session.authRequest = req;

// 3. (On client) use U2F API to request signature.
// u2f.sign([req], function(res) { /* send res back to server */ });

// 4. (On server) check signature using publicKey from user account.
var checkres = u2f.checkSignature(session.authRequest, res, user.publicKey);

if (checkres.successful) {
    // User is authenticated.
} else {
    // checkres.errorMessage will contain error text.
}
```

## Useful links

http://demo.yubico.com/u2f  
https://github.com/Yubico/python-u2flib-server  



## TODO

 * Provide instructions for client-side. How to get the 'u2f' namespace, what browsers are supported.
 * Change API to enable multiple keyhandle/publickey pairs for a single user.
 * Unpack registration certificate and check its own signature and time constraints.


# License

MIT

