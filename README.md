# U2F authentication library

This is a simple library to register and check signatures provided by U2F clients/devices.
It's intended to be used in Relying Parties - websites that want to add U2F 2-factor authentication
for their users.

To use U2F, it is recommended to familiarize yourself with [FIDO Alliance Specifications](https://fidoalliance.org/download/),
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

##### Server endpoints:

```javascript
const u2f = require('u2f');

// The app ID is a string used to uniquely identify your U2F app, for both registration requests and
// authentication requests. It is usually the fully qualified URL of your website. The website MUST
// be HTTPS, otherwise the registration will fail client-side.
const APP_ID = ...

function registrationChallengeHandler(req, res) {
  // 1. Check that the user is logged in.

  // 2. Generate a registration request and save it in the session.
  const registrationRequest = u2f.request(APP_ID);
  req.session.registrationRequest = registrationRequest;

  // 3. Send the registration request to the client, who will use the Javascript U2F API to sign
  // the registration request, and send it back to the server for verification. The registration
  // request is a JSON object containing properties used by the client to sign the request.
  return res.send(registrationRequest);
}

function registrationVerificationHandler(req, res) {
  // 4. Verify the registration response from the client against the registration request saved
  // in the server-side session.
  const result = u2f.checkRegistration(req.session.registrationRequest, req.body.registrationResponse);

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
const registrationRequest = ...  // Retrieve this from hitting the registration challenge endpoint

window.u2f.register(registrationRequest.appId, [registrationRequest], [], (registrationResponse) => {
  // Send this registration response to the registration verification server endpoint
});
```

### User Authentication Flow

##### Server endpoints:

```javascript
const u2f = require('u2f');

function authenticationChallengeHandler(req, res) {
  // 1. Check that the user is logged in using password authentication.

  // 2. Fetch the user's key handle from the server-side datastore. This field should have been
  // saved after the registration procedure.
  const keyHandle = ...

  // 3. Generate an authentication request and save it in the session. Use the same app ID that
  // was used in registration!
  const authRequest = u2f.request(APP_ID, keyHandle);
  req.session.authRequest = authRequest;

  // 4. Send the authentication request to the client, who will use the Javascript U2F API to sign
  // the authentication request, and send it back to the server for verification.
  return res.send(authRequest);
}

function authenticationVerificationHandler(req, res) {
  // 5. Fetch the user's public key from the server-side datastore. This field should have been
  // saved after the registration procedure.
  const publicKey = ...

  // 6. Verify the authentication response from the client against the authentication request saved
  // in the server-side session.
  const result = u2f.checkSignature(req.session.authRequest, req.body.authResponse, publicKey);

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
const authRequest = ...;  // Retrieve this from hitting the authentication challenge endpoint

window.u2f.sign(authRequest.appId, challenge, [authRequest], (authResponse) => {
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
