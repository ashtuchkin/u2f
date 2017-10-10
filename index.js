
var crypto = require('crypto');

// Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
function convertCertToPEM(cert) {
    if (!Buffer.isBuffer(cert))
        throw new Error("convertCertToPEM: cert must be buffer.")

    var type;
    if (cert.length == 65 && cert[0] == 0x04) {
        // If needed, we encode raw public key to ASN structure, adding metadata:
        // SEQUENCE {
        //   SEQUENCE {
        //      OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
        //      OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
        //   }
        //   BITSTRING <raw public key>
        // }
        // Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        cert = Buffer.concat([
            new Buffer("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            cert]);

        type = "PUBLIC KEY";
    } else {
        type = "CERTIFICATE";
    }

    // 2. To get PEM string, ASN structure then must be base64-encoded, split to
    // lines of 64 chars each and prefixed/postfixed with ---BEGIN/END PUBLIC KEY--- etc.

    var pemStr = "-----BEGIN "+type+"-----\n";
    for (var certStr = cert.toString('base64'); certStr.length > 64; certStr = certStr.slice(64))
        pemStr += certStr.slice(0, 64) + '\n';
    pemStr += certStr + '\n';
    pemStr += "-----END "+type+"-----\n";

    return pemStr;
}

// Check ECDSA+SHA256 signature of given data.
// cert is buffer containing ASN encoded certificate or raw publicKey of len 65
// signature is buffer (ASN encoded: SEQUENCE of 2 ec points)
// returns: true/false
function checkECDSASignature(data, cert, signature) {
    if (!Buffer.isBuffer(signature) || asnLen(signature) != signature.length)
        throw new Error("checkSignature: signature must be buffer of valid ASN/DER structure.");

    return crypto.createVerify("RSA-SHA256") // The actual signature alg is ECDSA and determined
            .update(data)                    // by ASN/DER data in public key. SHA256 is what we set here.
            .verify(convertCertToPEM(cert), signature);
}

// Our hash is always SHA256. Returns buffer.
function hash(data) {
    return crypto.createHash('SHA256').update(data).digest();
}

// Decode initial bytes of buffer as ASN and return the length of the encoded structure.
// See http://en.wikipedia.org/wiki/X.690
// Only SEQUENCE top-level identifier is supported (which covers all certs luckily)
function asnLen(buf) {
    if (buf.length < 2 || buf[0] != 0x30)
        throw new Error("Invalid data: Not a SEQUENCE ASN/DER structure");

    var len = buf[1];
    if (len & 0x80) { // long form
        var bytesCnt = len & 0x7F;
        if (buf.length < 2+bytesCnt)
            throw new Error("Invalid data: ASN structure not fully represented");
        len = 0;
        for (var i = 0; i < bytesCnt; i++)
            len = len*0x100 + buf[2+i];
        len += bytesCnt; // add bytes for length itself.
    }
    return len + 2; // add 2 initial bytes: type and length.
}

function toWebsafeBase64(buf) {
    return buf.toString('base64').replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g, '');
}



//==============================================================================
// Main API

// Generate request for client. Basically the same for registration and signature, except for the keyHandle.
function request(appId, keyHandle) {
    if (typeof appId !== 'string')
        throw new Error("U2F request(): appId must be provided.");

    var res = {
        version: "U2F_V2",
        appId: appId,
        challenge: toWebsafeBase64(crypto.randomBytes(32))
    };
    if (keyHandle)
        res.keyHandle = keyHandle;
    return res;
}

// Check registration data. We're checking correct challenge and certificate signature.
// request: {version, appId, challenge} - from user session, kept on server.
// registerData: {clientData, registrationData} - result of u2f.register
function checkRegistration(request, registerData) {
    if (typeof registerData !== 'object')
        return {errorMessage: "Invalid response from U2F token."};

    // Check registration error
    if (registerData.errorCode && registerData.errorCode != 0)
        return {
            errorMessage: registerData.errorMessage || "Error registering U2F token.",
            errorCode: registerData.errorCode,
        };

    // Unpack and check clientData, challenge.
    var clientData = new Buffer(registerData.clientData, 'base64');
    try {
        var clientDataObj = JSON.parse(clientData.toString('utf8'));
    }
    catch (e) {
        return {errorMessage: "Invalid clientData: not a valid JSON object"}
    }
    if (clientDataObj.challenge !== request.challenge)
        return {errorMessage: "Invalid challenge: not the one provided"};

    // Parse registrationData.
    var buf = new Buffer(registerData.registrationData, 'base64');
    var reserved = buf[0];                       buf = buf.slice(1);
    var publicKey = buf.slice(0, 65);            buf = buf.slice(65);
    var keyHandleLen = buf[0];                   buf = buf.slice(1);
    var keyHandle = buf.slice(0, keyHandleLen);  buf = buf.slice(keyHandleLen);
    var certLen = asnLen(buf);
    var certificate = buf.slice(0, certLen);     buf = buf.slice(certLen);
    var signLen = asnLen(buf);
    var signature = buf.slice(0, signLen);       buf = buf.slice(signLen);
    if (buf.length !== 0)
        console.error("U2F Registration Warning: registrationData has extra bytes: "+buf.toString('hex'));

    var reservedByte = new Buffer('00', 'hex');
    var appIdHash = hash(request.appId);
    var clientDataHash = hash(clientData);

    var signatureBase = Buffer.concat([reservedByte, appIdHash, clientDataHash, keyHandle, publicKey]);

    if (checkECDSASignature(signatureBase, certificate, signature))
        return {
            successful: true,
            publicKey: toWebsafeBase64(publicKey),
            keyHandle: toWebsafeBase64(keyHandle),
            certificate: certificate
        };
    else
        return {errorMessage: "Invalid signature."};
}


// Check signature data.
// request: {version, appId, challenge, keyHandle} - from user session, kept on server.
// signResult: {clientData, signatureData} - result of u2f.sign on client.
// publicKey: string from user account.
function checkSignature(request, signResult, publicKey) {
    if (typeof signResult !== 'object')
        return {errorMessage: "Invalid response from U2F token."};

    // Check registration error
    if (signResult.errorCode && signResult.errorCode != 0)
        return {
            errorMessage: signResult.errorMessage || "Error getting signature from U2F token.",
            errorCode: signResult.errorCode,
        };

    // Unpack and check clientData, challenge.
    var clientData = new Buffer(signResult.clientData, 'base64');
    try {
        var clientDataObj = JSON.parse(clientData.toString('utf8'));
    }
    catch (e) {
        return {errorMessage: "Invalid clientData: not a valid JSON object"}
    }
    if (clientDataObj.challenge !== request.challenge)
        return {errorMessage: "Invalid challenge: not the one provided"};

    // Parse signatureData
    var buf = new Buffer(signResult.signatureData, 'base64');
    var userPresenceFlag = buf.slice(0, 1);    buf = buf.slice(1);
    var counter = buf.slice(0, 4);             buf = buf.slice(4);
    var signLen = asnLen(buf);
    var signature = buf.slice(0, signLen);     buf = buf.slice(signLen);
    if (buf.length !== 0)
        console.error("U2F Authentication Warning: signatureData has extra bytes: "+buf.toString('hex'));

    var appIdHash = hash(request.appId);
    var clientDataHash = hash(clientData);

    var signatureBase = Buffer.concat([appIdHash, userPresenceFlag, counter, clientDataHash]);
    var cert = new Buffer(publicKey, 'base64');

    if (checkECDSASignature(signatureBase, cert, signature))
        return {
            successful: true,
            userPresent: (userPresenceFlag[0] & 1) === 1,
            counter: counter.readUInt32BE(0)
        };
    else
        return {errorMessage: "Invalid signature."};
}


// Set up appId as a convenience.
module.exports = {
    // Main API
    request: request,
    checkRegistration: checkRegistration,
    checkSignature: checkSignature,

    // Supplemental API, mostly for testing.
    _hash: hash,
    _checkECDSASignature: checkECDSASignature,
    _toWebsafeBase64: toWebsafeBase64,
}
