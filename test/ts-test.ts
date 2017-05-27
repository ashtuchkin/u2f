
import * as u2f from "../index";
import assert = require("assert");

interface RegistrationEntry {
    keyHandle: string;
    publicKey: string;
}

const USERNAME = "username";

describe("FIDO Specification v1.0-rd-20141008 (Typescript)", function () {
    describe("checkRegister", function () {
        it("should pass test from spec", function () {
            const REGISTRATION_APP_ID = "http://example.com";

            const certificate = new Buffer("3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df", 'hex');
            const clientData = new Buffer('{"typ":"navigator.id.finishEnrollment","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}');
            const publicKey = new Buffer("04b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9", "hex");
            const keyHandle = new Buffer("2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25", "hex");
            const registrationData = new Buffer("0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871", "hex");

            // produces RegistrationData
            function register_mock(request: u2f.Request): u2f.RegistrationData {
                return {
                    clientData: u2f._toWebsafeBase64(clientData),
                    registrationData: u2f._toWebsafeBase64(registrationData)
                }
            }

            function save_mock(username: string, keyHandle: string, publicKey: string): void {
            }

            // *********************************************
            //                Registration
            // *********************************************

            const registrationRequest = u2f.request(REGISTRATION_APP_ID);
            registrationRequest.challenge = "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo";
            // Client parses the request and produces registration data
            const registrationResponse = register_mock(registrationRequest);
            const registration = u2f.checkRegistration(registrationRequest, registrationResponse);

            
            let registrationResult: u2f.RegistrationResult;
            if ((<u2f.Error>registration).errorCode)
                console.log("Error during registration!");
            else {
                registrationResult = <u2f.RegistrationResult>registration;
                save_mock(USERNAME, registrationResult.keyHandle, registrationResult.publicKey);
                console.log("Registered!");
            }

            assert(registrationResult);
            assert.strictEqual(registrationResult.publicKey, u2f._toWebsafeBase64(publicKey));
            assert.strictEqual(registrationResult.keyHandle, u2f._toWebsafeBase64(keyHandle));
        });
    });

// *********************************************
//                Signature
// *********************************************

    describe("checkSignature", function () {
        it("should pass test from spec", function () {
            const SIGNATURE_APP_ID = "https://gstatic.com/securitykey/a/example.com";

            const publicKey = new Buffer("04d368f1b665bade3c33a20f1e429c7750d5033660c019119d29aa4ba7abc04aa7c80a46bbe11ca8cb5674d74f31f8a903f6bad105fb6ab74aefef4db8b0025e1d", 'hex');
            const clientData = new Buffer('{"typ":"navigator.id.getAssertion","challenge":"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}');
            const signatureData = new Buffer('0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f', 'hex');


            function sign_mock(request: u2f.Request): u2f.SignatureData {
                return {
                    clientData: u2f._toWebsafeBase64(clientData),
                    signatureData: u2f._toWebsafeBase64(signatureData)
                }
            }


            function load_mock(username: string): RegistrationEntry {
                return {
                    keyHandle: "",
                    publicKey: u2f._toWebsafeBase64(publicKey)
                }
            }


            const savedRegistration = load_mock(USERNAME);

            const signatureRequest = u2f.request(SIGNATURE_APP_ID, savedRegistration.keyHandle);
            signatureRequest.challenge = "opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o";

            // Client parses the request and produces signature data
            const signatureResponse = sign_mock(signatureRequest);
            const signature = u2f.checkSignature(signatureRequest, signatureResponse, savedRegistration.publicKey);

            let signatureResult: u2f.SignatureResult;
            if ((<u2f.Error>signature).errorCode)
                console.log("Error during signature!");
            else {
                signatureResult = <u2f.SignatureResult>signature;
                if (signatureResult.successful)
                    console.log("Authenticated!");
            }

            assert(signatureResult);
            assert.strictEqual(signatureResult.userPresent, true);
            assert.strictEqual(signatureResult.counter, 1);
        });
    });
});
