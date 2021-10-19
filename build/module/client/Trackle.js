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
const VERSION = '1.2.0';
const SYSTEM_EVENT_NAMES = ['iotready', 'trackle'];
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
const delay = async (ms) => await new Promise(resolve => setTimeout(resolve, ms));
EventEmitter.defaultMaxListeners = 100;
class Trackle extends EventEmitter {
    constructor(cloudOptions = {}) {
        super();
        this.forceTcp = false;
        this.otaUpdateEnabled = true;
        this.otaUpdatePending = false;
        this.otaUpdateForced = false;
        this.messageID = 0;
        this.wasOtaUpgradeSuccessful = false; // not used
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
            this.sentPacketCounterMap = new Map();
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
            this.sendHello(this.wasOtaUpgradeSuccessful);
            if (this.forceTcp) {
                this.helloTimeout = setTimeout(() => this.reconnect(new Error('Did not get hello response in 2 seconds')), 2000);
            }
            this.state = 'next';
            // Ping every 15 or 30 seconds
            this.pingInterval = setInterval(() => this.pingServer(), this.keepalive);
            this.isConnected = true;
            this.emit('connected');
            this.subscribe('trackle', this.handleSystemEvent);
            for await (const sub of this.subscriptionsMap.entries()) {
                await delay(50);
                this.sendSubscribe(sub[0], sub[1][0], sub[1][1], sub[1][2]);
            }
            // send getTime
            await delay(50);
            this.sendTimeRequest();
            // claimCode
            if (this.claimCode &&
                this.claimCode.length > 0 &&
                this.claimCode.length < 70) {
                await delay(50);
                this.publish('trackle/device/claim/code', this.claimCode, 'PRIVATE');
            }
            await delay(50);
            this.publish('trackle/hardware/ota_chunk_size', CHUNK_SIZE.toString(), 'PRIVATE');
            await delay(50);
            if (this.otaUpdateEnabled) {
                this.publish('trackle/device/updates/enabled', 'true', 'PRIVATE');
            }
            else {
                this.publish('trackle/device/updates/enabled', 'false', 'PRIVATE');
            }
            await delay(50);
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
                        // check if the firmware is the one defined in Cloud
                        if (crc && crc32(fileBuffer).toString('hex') !== crc) {
                            throw new Error('Firmware validation failed: crc not valid');
                        }
                        this.emit('otaReceived', {
                            fileContentBuffer: fileBuffer,
                            fileSize: fileBuffer.length
                        });
                    }
                    catch (err) {
                        this.publish('trackle/device/ota_result', err.message, 'PRIVATE');
                        this.emit('error', err);
                    }
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
                    this.sendVariable(varName, packet);
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
        this.sendHello = (wasOtaUpgradeSuccessful) => {
            const HELLO_FLAG_OTA_UPGRADE_SUCCESSFUL = 1;
            // const HELLO_FLAG_DIAGNOSTICS_SUPPORT = 2;
            const HELLO_FLAG_IMMEDIATE_UPDATES_SUPPORT = 4;
            let flags = wasOtaUpgradeSuccessful ? HELLO_FLAG_OTA_UPGRADE_SUCCESSFUL : 0;
            // flags |= HELLO_FLAG_DIAGNOSTICS_SUPPORT;
            flags |= HELLO_FLAG_IMMEDIATE_UPDATES_SUPPORT;
            const data = [
                this.productID >> 8,
                this.productID & 0xff,
                this.productFirmwareVersion >> 8,
                this.productFirmwareVersion & 0xff,
                0,
                flags,
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
        this.sendDescribe = async (descriptionFlags, serverPacket) => {
            const payload = descriptionFlags === DESCRIBE_ALL
                ? this.getDescription()
                : this.getDiagnostic();
            const packet = {
                ack: true,
                code: '2.05',
                messageId: this.messageID,
                payload,
                token: serverPacket.token
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
            if (packet.payload.length === 12 &&
                !this.otaUpdateEnabled &&
                !this.otaUpdateForced) {
                // Send ack with Service Unavailable
                const ackPacket = {
                    ack: true,
                    code: '5.03',
                    messageId: this.messageID,
                    token: packet.token
                };
                this.writeCoapData(ackPacket);
                this.emit('error', new Error(`Updates are not enabled`));
                return;
            }
            if (packet.payload.length === 12 || this.filesMap.has(fileName)) {
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
                        if (fileName && this.filesMap.has(fileName)) {
                            this.emit('fileReceived', {
                                fileContentBuffer,
                                fileName,
                                fileSize
                            });
                        }
                        else {
                            this.emit('otaFinished');
                            // check if is a valid OTA firmware file
                            try {
                                const fileBuffer = this.validateFirmwareFile(fileContentBuffer);
                                this.emit('otaReceived', {
                                    fileContentBuffer: fileBuffer,
                                    fileSize
                                });
                            }
                            catch (err) {
                                this.publish('trackle/device/ota_result', err.message, 'PRIVATE');
                                this.emit('error', err);
                            }
                        }
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
                this.emit('otaStarted');
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
        this.validateFirmwareFile = (fileContentBuffer) => {
            const fileContentBufferWithoutCrc = fileContentBuffer.slice(0, fileContentBuffer.length - 4);
            const fileContentBufferCrc = fileContentBuffer
                .slice(fileContentBuffer.length - 4, fileContentBuffer.length)
                .toString('hex');
            if (crc32(fileContentBufferWithoutCrc).toString('hex') !==
                fileContentBufferCrc) {
                throw new Error('Firmware validation failed: crc not valid');
            }
            return fileContentBuffer.slice(24, fileContentBuffer.length - 44);
        };
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
        this.sendVariable = async (varName, serverPacket) => {
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
                    variableValue = await retrieveValueCallback(varName);
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
        this.writeCoapData = (packet) => {
            if (packet.confirmable) {
                let sentPacketCounter = this.sentPacketCounterMap.get(packet.messageId);
                if (!sentPacketCounter) {
                    sentPacketCounter = 1;
                }
                else {
                    sentPacketCounter += 1;
                }
                if (sentPacketCounter <= 3) {
                    this.sentPacketCounterMap.set(packet.messageId, sentPacketCounter);
                    this.listenFor('COMPLETE', null, packet.messageId, 4000 * Math.pow(2, sentPacketCounter - 1)).catch(() => {
                        if (this.isConnected) {
                            this.writeCoapData(packet);
                        }
                    });
                }
                else {
                    this.reconnect(new Error('complete timeout for packet sent'));
                }
            }
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
        this.sendEvent = (name, data, nextMessageID, confirmable, eventType) => {
            if (!this.isConnected) {
                return false;
            }
            const payload = Buffer.from(data);
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