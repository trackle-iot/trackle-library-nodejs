/// <reference types="node" />
import ECKey from 'ec-key';
import NodeRSA from 'node-rsa';
declare class CryptoManager {
    static getServerKey: () => ECKey | NodeRSA;
    static setServerKey: (keyPEM: string, algorithm?: string) => void;
    static loadPrivateKey: (keyPEM: string, algorithm?: string) => ECKey | NodeRSA;
    static randomBytes: (count: number) => Buffer;
    static createHmacDigest: (ciphertext: Buffer, sessionKey: Buffer) => Buffer;
    private static serverKey;
    private privateKey;
    constructor(privateKey: NodeRSA);
    encrypt: (buffer: Buffer) => Buffer;
}
export default CryptoManager;
