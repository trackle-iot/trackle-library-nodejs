import crc32 from 'buffer-crc32';
import CoapPacket from 'coap-packet';
import dns from 'dns';
import { EventEmitter } from 'events';
import http from 'http';
import https from 'https';
import { Socket } from 'net';
import dtls from 'node-mbed-dtls-client';
import os from 'os';
import { URL } from 'url';
import ChunkingStream from '../lib/ChunkingStream';
import CoapMessages from '../lib/CoapMessages';
import CryptoManager from '../lib/CryptoManager';
import CryptoStream from '../lib/CryptoStream';
import CoapUriType from '../types/CoapUriType';
const COUNTER_MAX = 65536;
const EVENT_NAME_MAX_LENGTH = 64;
const FILES_MAX_NUMBER = 4;
const FUNCTIONS_MAX_NUMBER = 10;
const VARIABLES_MAX_NUMBER = 10;
const SUBSCRIPTIONS_MAX_NUMBER = 4;
const PRODUCT_FIRMWARE_VERSION = 0;
const SOCKET_TIMEOUT = 31000;
const DESCRIBE_METRICS = 1 << 2;
const DESCRIBE_APPLICATION = 1 << 1;
const DESCRIBE_SYSTEM = 1 << 0;
const DESCRIBE_ALL = DESCRIBE_APPLICATION | DESCRIBE_SYSTEM;
const CHUNK_SIZE = 512;
const SEND_EVENT_ACK_TIMEOUT = 5000;
const CLOUD_ADDRESS_TCP = 'device.trackle.io';
const CLOUD_PUBLIC_KEY_TCP = `-----BEGIN PUBLIC KEY-----\n
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7hEN7ub/klSKC6qBpFmT\n
/qZKQqdu4pS+2Y9/w7xb5BxQ7Ss+e8vKhRKvP1F2VdRy2UFym0qwBIKRQ3ha3Nbs\n
2f7zxEm5HHIpSEMCjrz+vQsSdtviYq4omiNzyUYmkkOxykVcncKrsNlU40psL648\n
DUxp4HL79Z+wudiyTMKpTnBlSt7n2w1Hh7/0t4q334qgSjpT78Xl895wW9wSWR/D\n
TZph/QzCPiHFnAiwCJ76UbnT30p9FheqSEAoFo8VOsTvg8CuLNeDPcuSmefPo2IN\n
J7dsEokhvOOziPovL0ubG4RbhwC6AMJaVU65mEN8yxcgx4vw5vJ4y+ly1ZKMZytK\n
NwIDAQAB\n
-----END PUBLIC KEY-----\n
\n`;
const CLOUD_ADDRESS_UDP = 'udp.device.trackle.io';
const CLOUD_PUBLIC_KEY_UDP = `-----BEGIN PUBLIC KEY-----\n
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKxmdyfKwLdHxffAr0ezRV9Z0Udec\n
CeFwQ0pbwkDASWc0yKT4tPf7tNA/zK8fqi4ddoLPOhoLQjgUbVRCBdxNJw==\n
-----END PUBLIC KEY-----\n
\n`;
const VERSION = '1.4.1';
const SYSTEM_EVENT_NAMES = ['iotready', 'trackle'];
export const updatePropertiesErrors = {
    BAD_REQUEST: -1,
    NOT_FOUND: -3,
    NOT_WRITABLE: -2
};
const getPlatformID = () => {
    const platform = os.platform();
    const arch = os.arch();
    switch (platform) {
        case 'darwin':
            return 102;
        case 'linux':
            if (arch === 'arm' || arch === 'arm64') {
                return 101;
            }
            return 103;
        case 'win32':
            return 770;
    }
    return 103; // linux default ??
};
EventEmitter.defaultMaxListeners = 100;
class Trackle extends EventEmitter {
    constructor(cloudOptions = {}) {
        super();
        this.forceTcp = false;
        this.otaUpdateEnabled = true;
        this.otaUpdatePending = false;
        this.otaUpdateForced = false;
        this.messageID = 0;
        // private sentPacketCounterMap: Map<number, number>;
        this.keepalive = 30000;
        this.forceTcpProtocol = () => {
            this.forceTcp = true;
            this.keepalive = 15000;
        };
        this.begin = async (deviceID, privateKey, productID, productFirmwareVersion, platformID) => {
            if (deviceID === '') {
                throw new Error(`You must define deviceID`);
            }
            if (deviceID.length !== 24) {
                throw new Error(`Wrong deviceID`);
            }
            this.deviceID = Buffer.from(deviceID, 'hex');
            if (!privateKey) {
                throw new Error(`You must define privateKey in PEM string or DER Buffer`);
            }
            this.privateKey = CryptoManager.loadPrivateKey(privateKey, this.forceTcp ? 'rsa' : 'ecc');
            let cloudPublicKey = this.forceTcp
                ? CLOUD_PUBLIC_KEY_TCP
                : CLOUD_PUBLIC_KEY_UDP;
            if (this.cloud.publicKeyPEM) {
                cloudPublicKey = this.cloud.publicKeyPEM;
            }
            try {
                CryptoManager.setServerKey(cloudPublicKey, this.forceTcp ? 'rsa' : 'ecc');
            }
            catch (err) {
                throw new Error('Cloud public key error. Are you using a tcp key without calling forceTcpProtocol()?');
            }
            this.serverKey = CryptoManager.getServerKey();
            if (this.cloud.address) {
                const index = this.cloud.address.indexOf('://');
                this.host =
                    index >= 0 ? this.cloud.address.substr(index + 3) : this.cloud.address;
            }
            else {
                this.host = this.forceTcp
                    ? CLOUD_ADDRESS_TCP
                    : `${deviceID}.${CLOUD_ADDRESS_UDP}`;
            }
            if (this.host !== 'localhost' && this.host !== '127.0.0.1') {
                try {
                    const addresses = await this.resolvePromise(this.host);
                    if (addresses && addresses.length > 0) {
                        this.host = addresses[0];
                    }
                }
                catch (err) {
                    throw new Error(`Could not resolve host address ${this.host}: ${err.message}`);
                }
            }
            this.port = this.cloud.port || (this.forceTcp ? 5683 : 5684);
            this.platformID = platformID || getPlatformID();
            this.productID = productID || COUNTER_MAX;
            this.productFirmwareVersion =
                productFirmwareVersion || PRODUCT_FIRMWARE_VERSION;
            this.isInitialized = true;
        };
        this.connect = async () => {
            if (this.isConnecting) {
                return;
            }
            if (!this.isInitialized) {
                throw new Error('You must initialize library calling begin before connect');
            }
            this.isConnecting = true;
            // this.sentPacketCounterMap = new Map<number, number>();
            if (!this.forceTcp) {
                const handshakeTimeout = setTimeout(() => {
                    this.reconnect(new Error('handshake timeout'));
                }, 5000);
                this.socket = dtls.connect({
                    debug: (process.env.DEBUG_MBED &&
                        parseInt(process.env.DEBUG_MBED, 10) > 0) ||
                        undefined,
                    host: this.host,
                    key: this.privateKey,
                    peerPublicKey: this.serverKey.toBuffer('spki'),
                    port: this.port
                }, (socket) => {
                    clearTimeout(handshakeTimeout);
                    this.emit('connect', {
                        host: this.host,
                        port: this.port
                    });
                    socket.on('data', this.onNewCoapMessage);
                    socket.on('error', (err) => {
                        this.reconnect(err);
                    });
                    socket.on('close', () => this.reconnect(new Error('dtls socket close')));
                    this.socket = socket;
                    this.decipherStream = socket;
                    this.cipherStream = socket;
                    this.finalizeHandshake();
                });
                this.socket.on('err', (_, msg) => this.reconnect(new Error(msg)));
            }
            else {
                this.state = 'nonce';
                this.socket = new Socket();
                this.socket.setTimeout(SOCKET_TIMEOUT);
                this.socket.on('data', this.onReadData);
                this.socket.on('error', this.reconnect);
                this.socket.on('close', () => this.reconnect(new Error('socket close')));
                this.socket.on('timeout', (err) => this.reconnect(err));
                this.socket.connect({
                    host: this.host,
                    port: this.port
                }, () => this.emit('connect', {
                    host: this.host,
                    port: this.port
                }));
            }
        };
        this.connected = () => this.isConnected;
        this.setClaimCode = (claimCode) => {
            this.claimCode = claimCode;
        };
        this.file = (fileName, mimeType, retrieveFileCallback) => {
            if (fileName.length > EVENT_NAME_MAX_LENGTH) {
                return false;
            }
            if (this.filesMap.size >= FILES_MAX_NUMBER) {
                return false;
            }
            this.filesMap.set(fileName, [mimeType, retrieveFileCallback]);
            return true;
        };
        this.post = (name, callFunctionCallback, functionFlags) => {
            if (name.length > EVENT_NAME_MAX_LENGTH) {
                return false;
            }
            if (this.functionsMap.size >= FUNCTIONS_MAX_NUMBER) {
                return false;
            }
            this.functionsMap.set(name, [functionFlags || '', callFunctionCallback]);
            return true;
        };
        this.get = (name, type, retrieveValueCallback) => {
            if (name.length > EVENT_NAME_MAX_LENGTH) {
                return false;
            }
            if (this.variablesMap.size >= VARIABLES_MAX_NUMBER) {
                return false;
            }
            this.variablesMap.set(name, [type, retrieveValueCallback]);
            return true;
        };
        this.setUpdatePropertiesCallback = (updatePropertiesCallback
        // propsFlags?: PropertiesFlags
        ) => {
            this.updatePropertiesCallback = updatePropertiesCallback;
            return true;
        };
        this.disconnect = () => {
            this.disconnectInternal();
            this.isDisconnected = true;
            this.emit('disconnect');
        };
        this.subscribe = (eventName, callback, subscriptionType, subscriptionDeviceID) => {
            if (eventName.length > EVENT_NAME_MAX_LENGTH) {
                return false;
            }
            if (this.subscriptionsMap.size >= SUBSCRIPTIONS_MAX_NUMBER) {
                return false;
            }
            if (subscriptionDeviceID && subscriptionDeviceID.length !== 24) {
                return false;
            }
            const handler = (packet) => {
                const uris = packet.options
                    .filter(o => o.name === 'Uri-Path')
                    .map(o => o.value.toString('utf8'));
                uris.shift(); // Remove E or e
                const name = uris.join('/');
                const data = packet.payload.toString('utf8');
                callback(name, data);
            };
            let type = 'ALL_DEVICES';
            if (subscriptionType && subscriptionType === 'MY_DEVICES') {
                type = 'MY_DEVICES';
            }
            this.subscriptionsMap.set(eventName, [handler, type, subscriptionDeviceID]);
            return true;
        };
        this.unsubscribe = (eventName) => {
            if (!this.isConnected) {
                return;
            }
            const subValue = this.subscriptionsMap.get(eventName);
            this.removeListener(eventName, subValue[0]);
        };
        this.sendProperties = async (properties) => {
            if (!this.isConnected) {
                return;
            }
            try {
                /* const props = Array.from(this.propsMap, ([name, [type, value]]) => ({ name, type, value })).filter(({ name }) => properties.includes(name)).reduce((acc, cur) => {
                  acc[cur.name] = cur.type === 'boolean' ? Boolean(cur.value) : cur.type === 'number' ? Number(cur.value) : cur.value;
                  return acc;
                }, {});*/
                JSON.parse(properties);
                return await this.publish('trackle/p', properties, 'PRIVATE');
            }
            catch (err) {
                this.emit('error', new Error('Properties: ' + err.message));
            }
        };
        this.publish = async (eventName, data, eventType, eventFlags, messageID) => {
            if (!this.isConnected) {
                return;
            }
            const nextMessageID = this.nextMessageID();
            const confirmable = this.forceTcp
                ? eventFlags && eventFlags === 'WITH_ACK'
                    ? true
                    : false
                : eventFlags && eventFlags === 'NO_ACK'
                    ? false
                    : true; // default true for udp
            const messageSent = this.sendEvent(eventName, data, nextMessageID, confirmable, eventType);
            // do not emit for internal events
            if (!eventName.startsWith('iotready') && !eventName.startsWith('trackle')) {
                this.emit('publish', {
                    data,
                    eventFlags,
                    eventName,
                    eventType,
                    messageID,
                    messageSent
                });
                if (messageSent && confirmable) {
                    try {
                        await this.listenFor('ACK', null, nextMessageID, SEND_EVENT_ACK_TIMEOUT);
                        this.emit('publishCompleted', { success: true, messageID });
                    }
                    catch (err) {
                        this.emit('publishCompleted', { success: false, messageID });
                    }
                }
            }
        };
        this.enableUpdates = () => {
            if (!this.otaUpdateEnabled) {
                this.otaUpdateEnabled = true;
                if (this.isConnected) {
                    this.publish('trackle/device/updates/enabled', 'true', 'PRIVATE');
                }
            }
        };
        this.disableUpdates = () => {
            if (this.otaUpdateEnabled) {
                this.otaUpdateEnabled = false;
                if (this.isConnected) {
                    this.publish('trackle/device/updates/enabled', 'false', 'PRIVATE');
                }
            }
        };
        this.updatesEnabled = () => this.otaUpdateEnabled;
        this.updatesPending = () => this.otaUpdatePending;
        this.getDiagnostic = () => Buffer.concat([Buffer.alloc(1, 0)]);
        this.getDescription = () => {
            const filesObject = {};
            Array.from(this.filesMap.keys()).forEach((key) => {
                filesObject[key] = this.filesMap.get(key);
            });
            const functions = Array.from(this.functionsMap.keys());
            const variablesObject = {};
            Array.from(this.variablesMap.keys()).forEach((key) => {
                variablesObject[key] = this.variablesMap.get(key)[0];
            });
            const description = JSON.stringify({
                f: functions,
                g: filesObject,
                m: [
                    {},
                    {},
                    {
                        d: [],
                        f: 's',
                        n: '1',
                        v: VERSION
                    },
                    {},
                    {}
                ],
                p: this.platformID,
                v: variablesObject
            });
            return Buffer.from(description);
        };
        this.resolvePromise = (host) => {
            return new Promise((resolve, reject) => {
                dns.resolve(host, (err, address) => {
                    if (err)
                        reject(err);
                    resolve(address);
                });
            });
        };
        this.emitWithPrefix = (eventName, packet) => this.eventNames()
            .filter((eventNamePrefix) => eventName.startsWith(eventNamePrefix))
            .forEach((eventNamePrefix) => this.emit(eventNamePrefix, packet));
        this.sendSubscribe = async (eventName, handler, subscriptionType, subscriptionDeviceID) => {
            if (!this.isConnected) {
                return;
            }
            this.on(eventName, handler);
            const messageID = this.nextMessageID();
            const options = [
                {
                    name: 'Uri-Path',
                    value: Buffer.from(`${CoapUriType.Subscribe}/${eventName}`)
                }
            ];
            if (subscriptionType === 'MY_DEVICES') {
                options.push({
                    name: 'Uri-Query',
                    value: Buffer.from('u')
                });
            }
            const packet = {
                code: 'GET',
                confirmable: true,
                messageId: messageID,
                options,
                payload: subscriptionType === 'MY_DEVICES' && subscriptionDeviceID
                    ? Buffer.from(subscriptionDeviceID, 'hex')
                    : undefined
            };
            this.writeCoapData(packet);
            try {
                await this.listenFor('ACK', null, messageID, SEND_EVENT_ACK_TIMEOUT);
                if (!SYSTEM_EVENT_NAMES.includes(eventName)) {
                    this.emit('subscribe', eventName);
                }
            }
            catch (err) {
                this.emit('error', new Error('Subscribe: ' + err.message));
            }
        };
        this.disconnectInternal = () => {
            if (this.isDisconnected) {
                return;
            }
            this.isConnecting = false;
            this.isConnected = false;
            this.state = 'nonce';
            if (this.decipherStream) {
                this.decipherStream.removeAllListeners();
            }
            if (this.socket) {
                this.socket.removeAllListeners();
                this.socket.destroy();
                this.socket = null;
            }
            this.subscriptionsMap.forEach((value, eventName) => {
                this.removeListener(eventName, value[0]);
            });
            if (this.pingInterval) {
                clearInterval(this.pingInterval);
                this.pingInterval = null;
            }
        };
        this.reconnect = (error) => {
            if (this.isDisconnected) {
                return;
            }
            if (error !== undefined) {
                if (error.code === 'ENOTFOUND') {
                    this.emit('connectionError', new Error('No server found at this address!'));
                    if (this.socket) {
                        this.socket.destroy();
                    }
                }
                else if (error.code === 'ECONNREFUSED') {
                    this.emit('connectionError', new Error('Connection refused! Please check the IP.'));
                    if (this.socket) {
                        this.socket.destroy();
                    }
                }
                else {
                    this.emit('connectionError', new Error(error.message));
                }
            }
            this.disconnectInternal();
            setTimeout(() => {
                this.emit('reconnect');
                this.connect();
            }, 5000);
        };
        this.onReadData = (data) => {
            switch (this.state) {
                case 'nonce': {
                    const payload = this.prepareDevicePublicKey(data);
                    if (this.socket) {
                        this.socket.write(this.serverKey.encrypt(payload));
                    }
                    this.state = 'set-session-key';
                    break;
                }
                case 'set-session-key': {
                    const cipherText = data.slice(0, 128);
                    const signedHMAC = data.slice(128);
                    const sessionKey = this.privateKey.decrypt(cipherText);
                    // Server creates a 20-byte HMAC of the ciphertext using SHA1 and the 40
                    // bytes generated in the previous step as the HMAC key.
                    const hash = CryptoManager.createHmacDigest(cipherText, sessionKey);
                    const decryptedHMAC = this.serverKey.decryptPublic(signedHMAC);
                    if (hash.compare(decryptedHMAC) === -1) {
                        throw new Error('HMAC did not match');
                    }
                    // The random session key has everything we need to create the crypto
                    // streams
                    const key = sessionKey.slice(0, 16);
                    const iv = sessionKey.slice(16, 32);
                    // const salt = sessionKey.slice(32); // not sure what this is for...
                    this.messageID = (sessionKey[32] << 8) | sessionKey[33];
                    // Create the crypto streams
                    this.decipherStream = new CryptoStream({
                        iv,
                        key,
                        streamType: 'decrypt'
                    });
                    this.cipherStream = new CryptoStream({
                        iv,
                        key,
                        streamType: 'encrypt'
                    });
                    const chunkingIn = new ChunkingStream({ outgoing: false });
                    const chunkingOut = new ChunkingStream({ outgoing: true });
                    // What I receive gets broken into message chunks, and goes into the
                    // decrypter
                    this.socket.pipe(chunkingIn).pipe(this.decipherStream);
                    // What I send goes into the encrypter, and then gets broken into message
                    // chunks
                    this.cipherStream.pipe(chunkingOut).pipe(this.socket);
                    this.socket.removeListener('data', this.onReadData);
                    this.decipherStream.on('data', this.onNewCoapMessage);
                    // send also for udp
                    this.finalizeHandshake();
                    break;
                }
                default: {
                    this.emit('error', new Error('Handshake error'));
                }
            }
        };
        this.finalizeHandshake = async () => {
            this.sendHello();
            if (this.forceTcp) {
                this.helloTimeout = setTimeout(() => this.reconnect(new Error('Did not get hello response in 2 seconds')), 2000);
            }
            this.state = 'next';
            // Ping every 15 or 30 seconds
            this.pingInterval = setInterval(() => this.pingServer(), this.keepalive);
            this.isConnected = true;
            this.emit('connected');
            this.sendDescribe(DESCRIBE_ALL);
            this.subscribe('trackle', this.handleSystemEvent);
            for await (const sub of this.subscriptionsMap.entries()) {
                this.sendSubscribe(sub[0], sub[1][0], sub[1][1], sub[1][2]);
            }
            // send getTime
            this.sendTimeRequest();
            // claimCode
            if (this.claimCode &&
                this.claimCode.length > 0 &&
                this.claimCode.length < 70) {
                this.publish('trackle/device/claim/code', this.claimCode, 'PRIVATE');
            }
            this.publish('trackle/hardware/ota_chunk_size', CHUNK_SIZE.toString(), 'PRIVATE');
            if (this.otaUpdateEnabled) {
                this.publish('trackle/device/updates/enabled', 'true', 'PRIVATE');
            }
            else {
                this.publish('trackle/device/updates/enabled', 'false', 'PRIVATE');
            }
            if (this.otaUpdateForced) {
                this.publish('trackle/device/updates/forced', 'true', 'PRIVATE');
            }
            else {
                this.publish('trackle/device/updates/forced', 'false', 'PRIVATE');
            }
        };
        this.handleSystemEvent = async (eventName, data) => {
            switch (eventName) {
                case 'trackle/device/reset':
                    switch (data) {
                        case 'dfu':
                            this.emit('dfu');
                            break;
                        case 'safe mode':
                            this.emit('safemode');
                            break;
                        case 'reboot':
                            this.emit('reboot');
                            break;
                    }
                    break;
                case 'trackle/device/updates/forced':
                    const newUpdateForcedData = data === 'true';
                    if (this.otaUpdateForced !== newUpdateForcedData) {
                        this.otaUpdateForced = newUpdateForcedData;
                        this.emit('firmwareUpdateForced', newUpdateForcedData);
                        this.publish('trackle/device/updates/forced', newUpdateForcedData.toString(), 'PRIVATE');
                    }
                    break;
                case 'trackle/device/updates/pending':
                    const newUpdatePendingData = data === 'true';
                    if (this.otaUpdatePending !== newUpdatePendingData) {
                        this.otaUpdatePending = newUpdatePendingData;
                        if (newUpdatePendingData) {
                            // true
                            this.emit('firmwareUpdatePending');
                            this.publish('trackle/device/updates/pending', '', 'PRIVATE');
                        }
                    }
                    break;
                case 'trackle/device/owners':
                    this.owners = data.split(',');
                    break;
                case 'trackle/device/update':
                    if (!this.otaUpdateEnabled && !this.otaUpdateForced) {
                        this.publish('trackle/device/ota_result', 'Updates are not enabled', 'PRIVATE');
                        this.emit('error', new Error('Updates are not enabled'));
                        return;
                    }
                    try {
                        const { crc, url } = JSON.parse(data);
                        const fileURL = new URL(url);
                        const protocol = fileURL.protocol === 'https:' ? https : http;
                        const fileBuffer = await new Promise((resolve, reject) => {
                            protocol
                                .get(url, res => {
                                const fileData = [];
                                res
                                    .on('data', chunk => {
                                    fileData.push(chunk);
                                })
                                    .on('end', () => {
                                    const bufferInt = Buffer.concat(fileData);
                                    resolve(bufferInt);
                                });
                            })
                                .on('error', err => {
                                reject(err);
                            });
                        });
                        const filename = url.substring(url.lastIndexOf('/') + 1);
                        // check if the firmware is the one defined in Cloud
                        if (!filename || !filename.endsWith('.bin')) {
                            throw new Error('Firmware validation failed: not a bin file');
                        }
                        // check if the firmware is the one defined in Cloud
                        if (crc && crc32(fileBuffer).toString('hex') !== crc) {
                            throw new Error('Firmware validation failed: crc not valid');
                        }
                        this.emit('otaRequest', {
                            fileContentBuffer: fileBuffer,
                            fileSize: fileBuffer.length
                        });
                    }
                    catch (err) {
                        this.publish('trackle/device/ota_result', err.message, 'PRIVATE');
                        this.emit('error', err);
                    }
                    break;
                case 'trackle/device/pin_code':
                    this.emit('pinCode', data);
                    break;
            }
        };
        this.onNewCoapMessage = async (data) => {
            const packet = CoapPacket.parse(data);
            if (packet.ack) {
                this.emit('COMPLETE', packet);
            }
            if (packet.code === '0.00' && packet.ack) {
                this.emit('ACK', packet);
            }
            if (packet.code === '0.00' && packet.confirmable) {
                this.emit('ping');
                this.sendPingAck(packet);
            }
            if (packet.code === '4.00' && packet.ack) {
                this.emit('error', new Error(packet.payload.toString('utf8')));
            }
            if (packet.code === '5.00' && packet.ack) {
                this.emit('error', new Error('server error'));
            }
            const uriOption = packet.options.find(option => option.name === 'Uri-Path');
            if (!uriOption) {
                return;
            }
            const coapPath = uriOption.value.toString('utf8');
            const messageType = coapPath.substring(0, coapPath.indexOf('/')) || coapPath;
            switch (messageType) {
                case CoapUriType.GetTime: {
                    this.emit('time', parseInt(packet.payload.toString('hex'), 16));
                    break;
                }
                case CoapUriType.Describe: {
                    const uriQuery = packet.options.find(option => option.name === 'Uri-Query');
                    const descriptionFlags = parseInt(uriQuery.value.toString('hex'), 16);
                    if (descriptionFlags === DESCRIBE_ALL ||
                        descriptionFlags === DESCRIBE_METRICS) {
                        this.sendDescribe(descriptionFlags, packet);
                    }
                    else {
                        this.emit('error', new Error(`Invalid DESCRIBE flags ${descriptionFlags}`));
                    }
                    break;
                }
                case CoapUriType.Function: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove f
                    const functionName = uris.join('/');
                    const args = packet.options
                        .filter(o => o.name === 'Uri-Query')
                        .map(o => o.value.toString('utf8'));
                    this.sendFunctionResult(functionName, args[0], args[1], packet);
                    break;
                }
                case CoapUriType.Hello: {
                    clearTimeout(this.helloTimeout);
                    this.helloTimeout = null;
                    break;
                }
                case CoapUriType.PrivateEvent:
                case CoapUriType.PublicEvent: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove E or e
                    this.emitWithPrefix(uris.join('/'), packet);
                    break;
                }
                case CoapUriType.Variable: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove v
                    const varName = uris.join('/');
                    const args = packet.options
                        .filter(o => o.name === 'Uri-Query')
                        .map(o => o.value.toString('utf8'));
                    this.sendVariable(varName, args[0], packet);
                    break;
                }
                case CoapUriType.UpdateBegin:
                case CoapUriType.UpdateDone:
                case CoapUriType.UpdateReady: {
                    if (packet.code === '0.02') {
                        this.receiveFile(packet);
                    }
                    else if (packet.code === '0.03') {
                        this.emit('UpdateDone', packet);
                    }
                    else if (packet.code === '2.04') {
                        this.emit('UpdateReady', packet);
                    }
                    break;
                }
                case CoapUriType.Chunk: {
                    this.emit('Chunk', packet);
                    break;
                }
                case CoapUriType.FileRequest: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove g
                    const fileName = uris.join('/');
                    this.sendFile(fileName, packet);
                    break;
                }
                case CoapUriType.SignalStart: {
                    const args = packet.options
                        .filter(o => o.name === 'Uri-Query')
                        .map(o => o.value.toString('hex'));
                    this.emit('signal', parseInt(args[0], 16) === 1);
                    this.sendSignalStartReturn(packet);
                    break;
                }
                case CoapUriType.UpdateProperty: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove p
                    const propName = uris.join('/');
                    const args = packet.options
                        .filter(o => o.name === 'Uri-Query')
                        .map(o => o.value.toString('utf8'));
                    this.sendUpdatePropResult(propName, args[0], packet);
                    break;
                }
                default: {
                    this.emit('error', new Error(`Coap URI ${coapPath} is not supported: ${packet}`));
                }
            }
        };
        this.prepareDevicePublicKey = (nonce) => 
        // Concat a bunch of data that we will send over encrypted with the
        // server public key.
        Buffer.concat([
            nonce,
            this.deviceID,
            this.privateKey.exportKey('pkcs8-public-der')
        ]);
        this.nextMessageID = () => {
            this.messageID += 1;
            if (this.messageID >= COUNTER_MAX) {
                this.messageID = 0;
            }
            return this.messageID;
        };
        this.sendHello = () => {
            const data = [
                this.productID >> 8,
                this.productID & 0xff,
                this.productFirmwareVersion >> 8,
                this.productFirmwareVersion & 0xff,
                0,
                0,
                this.platformID >> 8,
                this.platformID & 0xff,
                this.deviceID.length >> 8,
                this.deviceID.length & 0xff
            ];
            this.deviceID.forEach(bit => data.push(bit));
            const packet = {
                code: 'POST',
                messageId: this.nextMessageID(),
                options: [
                    {
                        name: 'Uri-Path',
                        value: Buffer.from(CoapUriType.Hello)
                    }
                ],
                payload: Buffer.from(data)
            };
            this.writeCoapData(packet);
        };
        this.sendTimeRequest = () => {
            const packet = {
                // ack: false,
                code: 'GET',
                confirmable: true,
                messageId: this.nextMessageID(),
                options: [
                    {
                        name: 'Uri-Path',
                        value: Buffer.from(CoapUriType.GetTime)
                    }
                ]
            };
            this.writeCoapData(packet);
        };
        this.sendDescribe = (descriptionFlags, serverPacket) => {
            const payload = descriptionFlags === DESCRIBE_ALL
                ? this.getDescription()
                : this.getDiagnostic();
            const packet = {
                ack: serverPacket ? true : false,
                code: serverPacket ? '2.05' : '0.02',
                confirmable: !serverPacket ? true : false,
                messageId: serverPacket ? this.messageID : this.nextMessageID(),
                options: !serverPacket
                    ? [
                        { name: 'Uri-Path', value: Buffer.from(CoapUriType.Describe) },
                        {
                            name: 'Uri-Query',
                            value: CoapMessages.toBinary(DESCRIBE_ALL, 'uint8')
                        }
                    ]
                    : undefined,
                payload,
                token: serverPacket ? serverPacket.token : undefined
            };
            this.writeCoapData(packet);
        };
        this.sendSignalStartReturn = async (serverPacket) => {
            const packet = {
                ack: true,
                code: '2.04',
                messageId: this.nextMessageID(),
                token: serverPacket.token
            };
            this.writeCoapData(packet);
        };
        this.sendPingAck = async (serverPacket) => {
            const packet = {
                ack: true,
                code: '0.00',
                messageId: serverPacket.messageId
            };
            this.writeCoapData(packet);
        };
        this.receiveFile = async (packet) => {
            // 1- get file info
            let chunksSize = packet.payload.readUInt16BE(1);
            if (!chunksSize || chunksSize === 0) {
                chunksSize = CHUNK_SIZE;
            }
            const fileSize = packet.payload.readInt32BE(3);
            const fileNameLength = packet.payload[12];
            const fileName = packet.payload.toString('utf8', 13, 13 + fileNameLength);
            /******************************/
            /* if (
              packet.payload.length === 12 &&
              !this.otaUpdateEnabled &&
              !this.otaUpdateForced
            ) {
              // Send ack with Service Unavailable
              const ackPacket = {
                ack: true,
                code: '5.03', // Service Unavailable
                messageId: this.messageID,
                token: packet.token
              };
              this.writeCoapData(ackPacket);
              this.emit('error', new Error(`Updates are not enabled`));
              return;
            } */
            if ( /* packet.payload.length === 12 ||*/this.filesMap.has(fileName)) {
                // 2- listen Chunk packet and fill fileContentBuffer
                const fileContentBuffer = Buffer.allocUnsafe(fileSize);
                const chunksNumber = Math.floor((fileSize + chunksSize - 1) / chunksSize);
                let chunksCounter = 0;
                const chunkMissedArray = [];
                const chunkHandler = (chunkPacket) => {
                    const chunkPacketOption = chunkPacket.options.filter((option) => option.name === 'Uri-Query');
                    const chunkCrc = chunkPacketOption[0].value.readUInt32BE(0);
                    const lastCrc = crc32.unsigned(chunkPacket.payload);
                    const chunkNumber = chunkPacketOption[1].value.readUInt16BE(0);
                    if (chunkCrc === lastCrc) {
                        chunksCounter += 1;
                        let chunkLength = chunksSize;
                        if (fileSize - chunksSize * chunkNumber < chunksSize) {
                            chunkLength = fileSize - chunksSize * chunkNumber;
                        }
                        chunkPacket.payload.copy(fileContentBuffer, chunksSize * chunkNumber, 0, chunkLength);
                    }
                    else {
                        // in fast OTA send only 1 ChunkMissed with messageIds array
                        chunkMissedArray.push(chunkNumber);
                    }
                    if (chunksNumber === chunksCounter) {
                        this.removeListener('Chunk', chunkHandler);
                        // if (fileName && this.filesMap.has(fileName)) {
                        this.emit('fileReceived', {
                            fileContentBuffer,
                            fileName,
                            fileSize
                        });
                        /*}  else {
                          this.emit('otaFinished');
                          // check if is a valid OTA firmware file
                          try {
                            const fileBuffer = this.validateFirmwareFile(fileContentBuffer);
                            this.emit('otaRequest', {
                              fileContentBuffer: fileBuffer,
                              fileSize
                            });
                          } catch (err) {
                            this.publish('trackle/device/ota_result', err.message, 'PRIVATE');
                            this.emit('error', err);
                          }
                        } */
                    }
                };
                this.on('Chunk', chunkHandler);
                /******************************/
                // 3- send UpdateReady packet in order to start receiving chunks
                const responsePacket = {
                    code: '2.04',
                    confirmable: false,
                    messageId: this.nextMessageID(),
                    payload: Buffer.from(CoapUriType.UpdateReady),
                    token: packet.token
                };
                this.writeCoapData(responsePacket);
                /******************************/
                // 4- wait for UpdateDone packet
                const updateDoneHandler = (updateDonePacket) => {
                    if (chunksNumber !== chunksCounter && chunkMissedArray.length > 0) {
                        // send UpdateDoneAckError
                        const updateDoneAckErrorPacket = {
                            ack: true,
                            code: '4.00',
                            confirmable: false,
                            messageId: this.nextMessageID(),
                            token: updateDonePacket.token
                        };
                        this.writeCoapData(updateDoneAckErrorPacket);
                        // in fast OTA send only 1 ChunkMissed with messageIds array
                        const chunkMissedBuffer = Buffer.allocUnsafe(2 * chunkMissedArray.length);
                        for (let i = 0; i < chunkMissedArray.length; i += 1) {
                            chunkMissedBuffer.writeUInt16BE(chunkMissedArray[i], i * 2);
                        }
                        const chunkMissedPacket = {
                            code: 'GET',
                            confirmable: true,
                            messageId: this.nextMessageID(),
                            options: [
                                { name: 'Uri-Path', value: Buffer.from(CoapUriType.Chunk) }
                            ],
                            payload: chunkMissedBuffer
                        };
                        this.writeCoapData(chunkMissedPacket);
                        // wait for server retries in sending chunks
                        setTimeout(() => {
                            this.removeListener('Chunk', chunkHandler);
                            this.removeListener('UpdateDone', updateDoneHandler);
                        }, 9000);
                    }
                    else {
                        // send UpdateDoneAck
                        const updateDoneAckPacket = {
                            ack: true,
                            code: '2.04',
                            confirmable: false,
                            messageId: this.nextMessageID(),
                            token: updateDonePacket.token
                        };
                        this.writeCoapData(updateDoneAckPacket);
                        this.removeListener('UpdateDone', updateDoneHandler);
                    }
                };
                this.on('UpdateDone', updateDoneHandler);
                /******************************/
            }
            else {
                // send UpdateAbort packet
                const responsePacket = {
                    code: '4',
                    confirmable: false,
                    messageId: this.nextMessageID(),
                    payload: Buffer.from('26'),
                    token: packet.token
                };
                this.writeCoapData(responsePacket);
                this.emit('error', new Error(`File ${fileName} not found`));
            }
        };
        /* private validateFirmwareFile = (fileContentBuffer: Buffer): Buffer => {
          const fileContentBufferWithoutCrc = fileContentBuffer.slice(
            0,
            fileContentBuffer.length - 4
          );
          const fileContentBufferCrc = fileContentBuffer
            .slice(fileContentBuffer.length - 4, fileContentBuffer.length)
            .toString('hex');
          if (
            crc32(fileContentBufferWithoutCrc).toString('hex') !==
            fileContentBufferCrc
          ) {
            throw new Error('Firmware validation failed: crc not valid');
          }
          return fileContentBuffer.slice(24, fileContentBuffer.length - 44);
        };*/
        this.sendFile = async (fileName, serverPacket) => {
            if (!this.isConnected) {
                return;
            }
            if (this.filesMap.has(fileName)) {
                const [, receiveFileCallback] = this.filesMap.get(fileName);
                let fileBuffer;
                try {
                    fileBuffer = await receiveFileCallback(fileName);
                    if (!fileBuffer || fileBuffer.length === 0) {
                        this.emit('error', new Error('File content error'));
                        return; // error
                    }
                    // 1- Send FileReturn to server
                    const packet = {
                        code: '2.04',
                        messageId: this.nextMessageID(),
                        payload: CoapMessages.toBinary(1, 'uint8'),
                        token: serverPacket.token
                    };
                    this.writeCoapData(packet);
                    /******************************/
                }
                catch (err) {
                    if (fileBuffer) {
                        this.messageID -= 1;
                    }
                    this.writeError(serverPacket, err.message, err.status || '5.00');
                    this.emit('error', new Error(err.message));
                }
                // 2- Prepare and send UpdateBegin packet
                const flags = 1; // fast ota available
                const chunkSize = CHUNK_SIZE;
                const fileSize = fileBuffer.length;
                const destFlag = 128;
                const destAddr = 0;
                const payloadArray = [
                    CoapMessages.toBinary(flags, 'uint8'),
                    CoapMessages.toBinary(chunkSize, 'uint16'),
                    CoapMessages.toBinary(fileSize, 'uint32'),
                    CoapMessages.toBinary(destFlag, 'uint8'),
                    CoapMessages.toBinary(destAddr, 'uint32')
                ];
                // add filename optional payloads for sending file
                if (fileName && fileName.length > 0) {
                    payloadArray.push(CoapMessages.toBinary(fileName.length, 'uint8'));
                    payloadArray.push(CoapMessages.toBinary(fileName, 'string'));
                }
                const packetBegin = {
                    code: 'POST',
                    confirmable: true,
                    messageId: this.nextMessageID(),
                    options: [
                        {
                            name: 'Uri-Path',
                            value: Buffer.from(CoapUriType.UpdateBegin)
                        }
                    ],
                    payload: Buffer.concat(payloadArray)
                };
                this.writeCoapData(packetBegin);
                /******************************/
                // 3- Wait for UpdateReady and send chunked buffer
                const updateReadyMessage = await this.listenFor('UpdateReady');
                if (updateReadyMessage) {
                    // generate buffer chunks
                    const bufferChunks = [];
                    let i = 0;
                    while (i < fileSize) {
                        const buffer = fileBuffer.slice(i, (i += chunkSize));
                        bufferChunks.push(buffer);
                    }
                    // send each chunk
                    let chunkIndex;
                    for (chunkIndex = 0; chunkIndex < bufferChunks.length; chunkIndex += 1) {
                        const buffer = Buffer.alloc(chunkSize);
                        bufferChunks[chunkIndex].copy(buffer, 0, 0, bufferChunks[chunkIndex].length);
                        buffer.fill(0, bufferChunks[chunkIndex].length, chunkSize);
                        const lastCrc = bufferChunks[chunkIndex]
                            ? crc32.unsigned(bufferChunks[chunkIndex])
                            : null;
                        // send
                        const options = [
                            {
                                name: 'Uri-Path',
                                value: Buffer.from(CoapUriType.Chunk)
                            },
                            {
                                name: 'Uri-Query',
                                value: CoapMessages.toBinary(lastCrc, 'crc')
                            },
                            {
                                name: 'Uri-Query',
                                value: CoapMessages.toBinary(chunkIndex, 'uint16')
                            }
                        ];
                        const chunkPacket = {
                            code: 'POST',
                            confirmable: true,
                            messageId: this.nextMessageID(),
                            options,
                            payload: buffer
                        };
                        this.writeCoapData(chunkPacket);
                    }
                    /******************************/
                    // 4- send UpdateDone packet
                    const packetDone = {
                        code: 'PUT',
                        confirmable: true,
                        messageId: this.nextMessageID(),
                        options: [
                            {
                                name: 'Uri-Path',
                                value: Buffer.from(CoapUriType.UpdateDone)
                            }
                        ]
                    };
                    this.writeCoapData(packetDone);
                    /******************************/
                    this.emit('fileSent', fileName);
                }
            }
            else {
                this.writeError(serverPacket, `File ${fileName} not found`, '4.04');
                this.emit('error', new Error(`File ${fileName} not found`));
            }
        };
        this.listenFor = async (eventName, token, messageId, timeoutMs) => {
            const tokenHex = token ? Buffer.from([token]).toString('hex') : null;
            return new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    cleanUpListeners();
                    reject(new Error(`Request timed out ${eventName}`));
                }, timeoutMs || this.keepalive * 2);
                // adds a one time event
                const handler = (packet) => {
                    clearTimeout(timeout);
                    const packetTokenHex = packet.token.toString('hex');
                    if (tokenHex && tokenHex !== packetTokenHex) {
                        // 'Tokens did not match'
                        return;
                    }
                    if (messageId &&
                        (messageId !== packet.messageId || parseFloat(packet.code) >= 4)) {
                        return;
                    }
                    cleanUpListeners();
                    resolve(packet);
                };
                const disconnectHandler = () => {
                    cleanUpListeners();
                    reject();
                };
                const cleanUpListeners = () => {
                    this.removeListener(eventName, handler);
                    this.removeListener('disconnect', disconnectHandler);
                };
                this.on(eventName, handler);
                this.on('disconnect', disconnectHandler);
            });
        };
        this.pingServer = () => {
            if (!this.isConnected) {
                return;
            }
            if (!this.forceTcp) {
                this.socket.dumbPing();
                return;
            }
            const packet = {
                code: '0',
                confirmable: true,
                messageId: this.nextMessageID()
            };
            this.writeCoapData(packet);
        };
        this.writeError = (serverPacket, message, responseCode) => {
            const packet = {
                ack: true,
                code: responseCode,
                confirmable: false,
                messageId: serverPacket.messageId,
                payload: Buffer.from(message)
            };
            this.writeCoapData(packet);
        };
        this.sendFunctionResult = async (functionName, args, caller, serverPacket) => {
            if (!this.isConnected) {
                return;
            }
            if (args.length > 622) {
                this.writeError(serverPacket, 'Args max length is 622 bytes', '4.00');
                this.emit('error', new Error('Args max length is 622 bytes'));
                return;
            }
            if (this.functionsMap.has(functionName)) {
                const [functionFlags, callFunctionCallback] = this.functionsMap.get(functionName);
                if (functionFlags === 'OWNER_ONLY' &&
                    (!this.owners || !this.owners.includes(caller))) {
                    this.writeError(serverPacket, 'Forbidden: only owners can call this function', '4.03');
                    this.emit('error', new Error('Forbidden'));
                    return;
                }
                let returnValue;
                try {
                    returnValue = await callFunctionCallback(args);
                    const packet = {
                        code: '2.04',
                        messageId: this.nextMessageID(),
                        payload: CoapMessages.toBinary(returnValue, 'int32'),
                        token: serverPacket.token
                    };
                    this.writeCoapData(packet);
                }
                catch (err) {
                    if (returnValue) {
                        this.messageID -= 1;
                    }
                    this.writeError(serverPacket, err.message, err.status || '5.00');
                    this.emit('error', new Error(err.message));
                }
            }
            else {
                this.writeError(serverPacket, `Function ${functionName} not found`, '4.04');
                this.emit('error', new Error(`Function ${functionName} not found`));
            }
        };
        this.sendVariable = async (varName, args, serverPacket) => {
            if (!this.isConnected) {
                return;
            }
            let hasName = varName;
            if (varName.indexOf('/') >= -1) {
                hasName = varName.split('/')[0];
            }
            if (this.variablesMap.has(hasName)) {
                const [type, retrieveValueCallback] = this.variablesMap.get(hasName);
                let variableValue;
                try {
                    variableValue = await retrieveValueCallback(args);
                    if ((type === 'string' || type === 'json') &&
                        JSON.stringify(variableValue).length > 622) {
                        this.writeError(serverPacket, 'Value max length is 622 bytes', '5.00');
                        this.emit('error', new Error('Value max length is 622 bytes'));
                        return;
                    }
                    const packet = {
                        code: '2.05',
                        messageId: this.nextMessageID(),
                        payload: CoapMessages.toBinary(variableValue, type),
                        token: serverPacket.token
                    };
                    this.writeCoapData(packet);
                }
                catch (err) {
                    if (variableValue) {
                        this.messageID -= 1;
                    }
                    this.writeError(serverPacket, err.message, err.status || '5.00');
                    this.emit('error', new Error(err.message));
                }
            }
            else {
                this.writeError(serverPacket, `Variable ${varName} not found`, '4.04');
                this.emit('error', new Error(`Variable ${varName} not found`));
            }
        };
        this.sendUpdatePropResult = async (property, value, serverPacket) => {
            if (!this.isConnected) {
                return;
            }
            if (value.length > 622) {
                this.writeError(serverPacket, 'Args max length is 622 bytes', '4.00');
                this.emit('error', new Error('Args max length is 622 bytes'));
                return;
            }
            if (this.updatePropertiesCallback) {
                let returnValue;
                try {
                    returnValue = await this.updatePropertiesCallback(property, value);
                    const packet = {
                        code: '2.04',
                        messageId: this.nextMessageID(),
                        payload: CoapMessages.toBinary(returnValue, 'int32'),
                        token: serverPacket.token
                    };
                    this.writeCoapData(packet);
                }
                catch (err) {
                    if (returnValue) {
                        this.messageID -= 1;
                    }
                    this.writeError(serverPacket, err.message, err.status || '5.00');
                    this.emit('error', new Error(err.message));
                }
            }
            else {
                this.writeError(serverPacket, 'setUpdatePropertiesCallback not defined', '5.00');
                this.emit('error', new Error('setUpdatePropertiesCallback not defined'));
            }
        };
        this.writeCoapData = (packet) => {
            /* if (packet.confirmable) {
              let sentPacketCounter = this.sentPacketCounterMap.get(packet.messageId);
              if (!sentPacketCounter) {
                sentPacketCounter = 1;
              } else {
                sentPacketCounter += 1;
              }
              if (sentPacketCounter <= 3) {
                this.sentPacketCounterMap.set(packet.messageId, sentPacketCounter);
                this.listenFor(
                  'COMPLETE',
                  null,
                  packet.messageId,
                  4000 * Math.pow(2, sentPacketCounter - 1)
                ).catch(() => {
                  if (this.isConnected) {
                    this.writeCoapData(packet);
                  }
                });
              } else {
                this.reconnect(new Error('complete timeout for packet sent'));
              }
            }*/
            const packetBuffer = CoapPacket.generate(packet);
            return this.writeData(packetBuffer);
        };
        this.writeData = (packet) => {
            try {
                if (this.socket) {
                    return this.cipherStream.write(packet);
                }
                return false;
            }
            catch (ignore) {
                this.emit('error', new Error(`Write data error: ${ignore}`));
                return false;
            }
        };
        this.sendEvent = (name, data = null, nextMessageID, confirmable, eventType) => {
            if (!this.isConnected) {
                return false;
            }
            const payload = data ? Buffer.from(data) : undefined;
            const packet = {
                code: 'POST',
                confirmable,
                messageId: nextMessageID,
                options: [
                    {
                        name: 'Uri-Path',
                        value: Buffer.from(`${eventType && eventType === 'PRIVATE'
                            ? CoapUriType.PrivateEvent
                            : CoapUriType.PublicEvent}/${name}`)
                    }
                ],
                payload
            };
            return this.writeCoapData(packet);
        };
        this.filesMap = new Map();
        this.functionsMap = new Map();
        this.subscriptionsMap = new Map();
        this.variablesMap = new Map();
        this.cloud = cloudOptions;
    }
}
export default new Trackle();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVHJhY2tsZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9jbGllbnQvVHJhY2tsZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEtBQUssTUFBTSxjQUFjLENBQUM7QUFDakMsT0FBTyxVQUFVLE1BQU0sYUFBYSxDQUFDO0FBQ3JDLE9BQU8sR0FBRyxNQUFNLEtBQUssQ0FBQztBQUV0QixPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sUUFBUSxDQUFDO0FBQ3RDLE9BQU8sSUFBSSxNQUFNLE1BQU0sQ0FBQztBQUN4QixPQUFPLEtBQUssTUFBTSxPQUFPLENBQUM7QUFDMUIsT0FBTyxFQUFFLE1BQU0sRUFBRSxNQUFNLEtBQUssQ0FBQztBQUM3QixPQUFPLElBQUksTUFBTSx1QkFBdUIsQ0FBQztBQUV6QyxPQUFPLEVBQUUsTUFBTSxJQUFJLENBQUM7QUFDcEIsT0FBTyxFQUFFLEdBQUcsRUFBRSxNQUFNLEtBQUssQ0FBQztBQUUxQixPQUFPLGNBQWMsTUFBTSx1QkFBdUIsQ0FBQztBQUNuRCxPQUFPLFlBQVksTUFBTSxxQkFBcUIsQ0FBQztBQUMvQyxPQUFPLGFBQWEsTUFBTSxzQkFBc0IsQ0FBQztBQUNqRCxPQUFPLFlBQVksTUFBTSxxQkFBcUIsQ0FBQztBQUMvQyxPQUFPLFdBQVcsTUFBTSxzQkFBc0IsQ0FBQztBQUUvQyxNQUFNLFdBQVcsR0FBRyxLQUFLLENBQUM7QUFDMUIsTUFBTSxxQkFBcUIsR0FBRyxFQUFFLENBQUM7QUFDakMsTUFBTSxnQkFBZ0IsR0FBRyxDQUFDLENBQUM7QUFDM0IsTUFBTSxvQkFBb0IsR0FBRyxFQUFFLENBQUM7QUFDaEMsTUFBTSxvQkFBb0IsR0FBRyxFQUFFLENBQUM7QUFDaEMsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLENBQUM7QUFFbkMsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLENBQUM7QUFDbkMsTUFBTSxjQUFjLEdBQUcsS0FBSyxDQUFDO0FBRTdCLE1BQU0sZ0JBQWdC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