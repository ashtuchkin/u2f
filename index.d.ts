// Type definitions for u2f 0.1.2
// Project: https://github.com/ashtuchkin/u2f
// Definitions by: Clement Michaud <https://github.com/clems4ever>
// Definitions: https://github.com/ashtuchkin/u2f
// TypeScript Version: 2.1

export interface Request {
    version: "U2F_V2";
    appId: string;
    challenge: string;
    keyHandle?: string;
}

export interface RegistrationData {
    clientData: string;
    registrationData: string;
    errorCode?: number;
}

export interface RegistrationResult {
    successful: true;
    publicKey: string;
    keyHandle: string;
    certificate: Buffer;
}

export interface SignatureData {
    clientData: string;
    signatureData: string;
    errorCode?: number;
}

export interface SignatureResult {
    successful: boolean;
    userPresent: boolean;
    counter: number;
}

export interface Error {
    errorCode: number;
    errorMessage: string;
}

export function request(appId: string, keyHandle?: string): Request;
export function checkRegistration(request: Request, registerData: RegistrationData): RegistrationResult | Error;
export function checkSignature(request: Request, signData: SignatureData, publicKey: string): SignatureResult | Error;

// For testing purposes
export function _toWebsafeBase64(buffer: Buffer): string;

