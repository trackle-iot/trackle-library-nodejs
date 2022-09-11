/// <reference types="node" />
import { EventEmitter } from 'events';
declare type EventType = 'PRIVATE' | 'PUBLIC';
declare type EventFlags = 'WITH_ACK' | 'NO_ACK';
declare type FunctionFlags = 'OWNER_ONLY';
declare type SubscriptionType = 'ALL_DEVICES' | 'MY_DEVICES';
export interface ICloudOptions {
    address?: string;
    publicKeyPEM?: string;
    port?: number;
}
export interface IProperty {
    propName: string;
    value: number;
    sync: boolean;
    writable: boolean;
}
export declare const updatePropertyErrors: {
    BAD_REQUEST: number;
    NOT_FOUND: number;
    NOT_WRITABLE: number;
};
declare class Trackle extends EventEmitter {
    cloud: ICloudOptions;
    private cipherStream;
    private decipherStream;
    private deviceID;
    private forceTcp;
    private otaUpdateEnabled;
    private otaUpdatePending;
    private otaUpdateForced;
    private helloTimeout;
    private host;
    private isInitialized;
    private isConnected;
    private isConnecting;
    private isDisconnected;
    private messageID;
    private owners;
    private pingInterval;
    private platformID;
    private productFirmwareVersion;
    private productID;
    private port;
    private privateKey;
    private sendPropsChangedInterval;
    private serverKey;
    private socket;
    private state;
    private filesMap;
    private functionsMap;
    private propsMap;
    private propsChangedArray;
    private subscriptionsMap;
    private variablesMap;
    private sentPacketCounterMap;
    private keepalive;
    private claimCode;
    private updatePropertyCallback;
    constructor(cloudOptions?: ICloudOptions);
    forceTcpProtocol: () => void;
    begin: (deviceID: string, privateKey: string | Buffer, productID?: number, productFirmwareVersion?: number, platformID?: number) => Promise<void>;
    connect: () => Promise<void>;
    connected: () => boolean;
    setClaimCode: (claimCode: string) => void;
    file: (fileName: string, mimeType: string, retrieveFileCallback: (fileName: string) => Promise<Buffer>) => boolean;
    post: (name: string, callFunctionCallback: (args: string, caller?: string) => number | Promise<number>, functionFlags?: FunctionFlags) => boolean;
    get: (name: string, type: string, retrieveValueCallback: (args?: string) => any | Promise<any>) => boolean;
    prop: (name: string, value: number, sync?: boolean, writable?: boolean) => boolean;
    updatePropValue: (name: string, value: number) => boolean;
    setUpdatePropertyCallback: (updatePropertyCallback: (name: string, value: number, caller?: string) => number | Promise<number>) => boolean;
    disconnect: () => void;
    subscribe: (eventName: string, callback: (event: string, data: string) => void, subscriptionType?: SubscriptionType, subscriptionDeviceID?: string) => boolean;
    unsubscribe: (eventName: string) => void;
    /**
     * Send properties
     * @param properties: string[] - array of property names to send. if passed empty do not send anything
     */
    sendProperties: (properties?: string[]) => Promise<void>;
    publish: (eventName: string, data?: string, eventType?: EventType, eventFlags?: EventFlags, messageID?: string) => Promise<void>;
    enableUpdates: () => void;
    disableUpdates: () => void;
    updatesEnabled: () => boolean;
    updatesPending: () => boolean;
    private getDiagnostic;
    private getDescription;
    private resolvePromise;
    private emitWithPrefix;
    private sendSubscribe;
    private disconnectInternal;
    private reconnect;
    private onReadData;
    private finalizeHandshake;
    private handleSystemEvent;
    private onNewCoapMessage;
    private prepareDevicePublicKey;
    private nextMessageID;
    private sendHello;
    private sendTimeRequest;
    private sendDescribe;
    private sendSignalStartReturn;
    private sendPingAck;
    private receiveFile;
    private sendFile;
    private listenFor;
    private pingServer;
    private writeError;
    private sendFunctionResult;
    private sendVariable;
    private sendUpdatePropResult;
    private writeCoapData;
    private writeData;
    private sendEvent;
}
declare const _default: Trackle;
export default _default;
