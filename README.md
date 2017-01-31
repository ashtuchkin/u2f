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

##### Server endpoint (registration challenge):

```javascript
const u2f = require('u2f');

function handler(req, res) {
  // 1. Check that the user is logged in.

  // 2. Generate a registration request and save it in the session.
  // The app ID is usually the fully qualified URL of your website. The website MUST be HTTPS, or
  // else the registration will fail client-side.
  const registrationReq = u2f.request('<appId>');
  req.session.registrationReq = registrationReq;

  // 3. Send the registration request to the client, who will use the Javascript U2F API to sign
  // the registration request, and send it back to the server for verification.
  return res.send(registrationReq);
}
```

##### Server endpoint (registration verification):

```javascript
const u2f = require('u2f');

function handler(req, res) {
  // 4. Verify the registration response from the client against the registration request saved
  // in the server-side session.
  const result = u2f.checkRegistration(req.session.registrationReq, req.body.registrationRes);

  if (result.successful) {
    // Success!
    // Save result.publicKey and result.keyHandle to the server-side datastore, associated with
    // this user.
    return res.sendStatus(200);
  }

  // result.errorMessage is defined with an English-language description of the error.
  return res.send({result});
}
```

##### Client logic:

Note that the `window.u2f` object is defined in the official [Javascript U2F API](https://github.com/google/u2f-ref-code), for which a polyfill is [available as an npm module](https://www.npmjs.com/package/u2f-api-polyfill).

```javascript
const registrationReq = ...  // Retrieve this from hitting the registration challenge endpoint
const {appId, version, challenge} = registrationReq;

window.u2f.register(appId, [{version, challenge}], [], (registrationRes) => {
  // Send this registration response to the registration verification server endpoint
});
```

### User Authentication Flow

##### Server endpoint (authentication challenge):

```javascript
const u2f = require('u2f');

function handler(req, res) {
  // 1. Check that the user is logged in.

  // 2. Fetch the user's key handle from the server-side datastore. This field should have been
  // saved after the registration procedure.
  const keyHandle = ...

  // 3. Generate an authentication request and save it in the session. Use the same app ID that
  // was used in registration!
  const authReq = u2f.request('<appId>', keyHandle);
  req.session.authReq = authReq;

  // 4. Send the authentication request to the client, who will use the Javascript U2F API to sign
  // the authentication request, and send it back to the server for verification.
  return res.send(authReq);
}
```

##### Server endpoint (authentication verification):

```javascript
const u2f = require('u2f');

function handler(req, res) {
  // 4. Verify the authentication response from the client against the authentication request saved
  // in the server-side session.
  const result = u2f.checkSignature(req.session.authReq, req.body.authRes);

  if (result.successful) {
    // Success!
    // User is authenticated.
    return res.sendStatus(200);
  }

  // result.errorMessage is defined with an English-language description of the error.
  return res.send({result});
}
```

##### Client logic:

```javascript
const authReq = ...;  // Retrieve this from hitting the authentication challenge endpoint
const {appId, challenge, version, keyHandle} = authReq;

window.u2f.sign(appId, challenge, [{version, keyHandle}], (authRes) => {
  // Send this authentication response to the authentication verification server endpoint
});
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
