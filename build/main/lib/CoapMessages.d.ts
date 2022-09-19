/// <reference types="node" />
export default class CoapMessages {
    static getTypeIntFromName: (name: string) => number;
    static toBinary: (value: string | number | Buffer | object, type?: string) => Buffer;
}
