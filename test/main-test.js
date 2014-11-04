
var assert = require('assert'),
    u2flib = require('../');

describe("Utility functions", function() {
    describe("_checkECDSASignature", function() {
        var publicKey = new Buffer('046057f9a14704cd947541320c2bd8895913462cf497b46d60644fbb42d3296133ab0b1e482258cccbdfee814c8bbd290ab0367d42955967f382e7d455f1d465ea', 'hex');
        var signature = new Buffer('3046022100a68a9838a687c5afe802e89d7c7ca3f4b564377e6dca267ecc5822259b9b1379022100a6f29a5f1b520f84d643009a1f11aaf626a5c3ab9bf8daa555e791113236dd70', 'hex');
        var data = new Buffer('8ad60b27d2abca206a71184aa31cd28c0cc1d86022713798051be8bc96fed51701000000013b88f7ab5683bbd61d1a789b05aaabea34a03365a94c7dbfc2f3e84ce86d9c81', 'hex');

        it("should pass sample test", function() {
            assert(u2flib._checkECDSASignature(data, publicKey, signature));
        });

        it("should not pass if data is different", function() {
            var data2 = Buffer.concat([data, new Buffer('00', 'hex')]);
            assert(!u2flib._checkECDSASignature(data2, publicKey, signature));
        });

        it("should not pass if signature is different", function() {
            var sig2 = new Buffer(signature.toString('hex'), 'hex');
            sig2[25]++;
            assert(!u2flib._checkECDSASignature(data, publicKey, sig2));
        });
    });
});

// From the bottom of https://fidoalliance.org/specs/fido-u2f-raw-message-formats-v1.0-rd-20141008.pdf
describe("FIDO Specification v1.0-rd-20141008", function () {
    describe("checkRegister", function () {
        it("should pass test from spec", function () {
            var appId = "http://example.com";
            var certificate = new Buffer("3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df", 'hex');
            var clientData = '{"typ":"navigator.id.finishEnrollment","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}';
            var publicKey = new Buffer("04b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9", "hex");
            var keyHandle = new Buffer("2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25", "hex");
            var registrationData = new Buffer("0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871", "hex");
            
            assert.equal(u2flib._hash(clientData).toString('hex'), "4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb");
            assert.equal(u2flib._hash(appId).toString('hex'), "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4");

            var request = u2flib.request(appId);
            request.challenge = "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo"; // We have a fixed challenge.

            var result = {
                clientData: u2flib._toWebsafeBase64(new Buffer(clientData)),
                registrationData: u2flib._toWebsafeBase64(registrationData)
            };

            var res = u2flib.checkRegistration(request, result);
            
            assert(res);
            assert.strictEqual(res.publicKey, u2flib._toWebsafeBase64(publicKey));
            assert.strictEqual(res.keyHandle, u2flib._toWebsafeBase64(keyHandle));
            //assert.strictEqual(res.certificate, certificate);
        });
    })

    describe("checkSignature", function () {
        it("should pass test from spec", function () {
            var publicKey = new Buffer("04d368f1b665bade3c33a20f1e429c7750d5033660c019119d29aa4ba7abc04aa7c80a46bbe11ca8cb5674d74f31f8a903f6bad105fb6ab74aefef4db8b0025e1d", 'hex');
            var appId = "https://gstatic.com/securitykey/a/example.com";
            var clientData = '{"typ":"navigator.id.getAssertion","challenge":"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}';
            var signatureData = new Buffer('0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f', 'hex');

            assert.equal(u2flib._hash(clientData).toString('hex'), "ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57");
            assert.equal(u2flib._hash(appId).toString('hex'), "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca");

            var request = u2flib.request(appId, '');
            request.challenge = "opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o"; // We have a fixed challenge.

            var signResult = {
                clientData: u2flib._toWebsafeBase64(new Buffer(clientData)),
                signatureData: u2flib._toWebsafeBase64(signatureData),
            };
            var res = u2flib.checkSignature(request, signResult, u2flib._toWebsafeBase64(publicKey));
            assert(res);
            assert.strictEqual(res.userPresent, true);
            assert.strictEqual(res.counter, 1);
        });
    })

});



