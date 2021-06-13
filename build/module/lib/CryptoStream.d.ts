/// <reference types="node" />
import { Transform } from 'stream';
export declare type CryptoStreamType = 'decrypt' | 'encrypt';
interface ICryptoStreamOptions {
    iv: Buffer;
    key: Buffer;
    streamType: CryptoStreamType;
}
declare class CryptoStream extends Transform {
    private key;
    private iv;
    private streamType;
    constructor(options: ICryptoStreamOptions);
    _transform: (chunk: Buffer, encoding: string, callback: () => any) => void;
}
export default CryptoStream;
