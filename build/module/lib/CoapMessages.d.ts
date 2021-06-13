/// <reference types="node" />
export default class CoapMessages {
    static toBinary: (value: string | number | Buffer | object, type?: string) => Buffer;
}
