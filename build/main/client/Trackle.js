"use strict";
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_crc32_1 = __importDefault(require("buffer-crc32"));
const coap_packet_1 = __importDefault(require("coap-packet"));
const dns_1 = __importDefault(require("dns"));
const events_1 = require("events");
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const net_1 = require("net");
const node_mbed_dtls_client_1 = __importDefault(require("node-mbed-dtls-client"));
const os_1 = __importDefault(require("os"));
const url_1 = require("url");
const ChunkingStream_1 = __importDefault(require("../lib/ChunkingStream"));
const CoapMessages_1 = __importDefault(require("../lib/CoapMessages"));
const CryptoManager_1 = __importDefault(require("../lib/CryptoManager"));
const CryptoStream_1 = __importDefault(require("../lib/CryptoStream"));
const CoapUriType_1 = __importDefault(require("../types/CoapUriType"));
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
    const platform = os_1.default.platform();
    const arch = os_1.default.arch();
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
events_1.EventEmitter.defaultMaxListeners = 100;
class Trackle extends events_1.EventEmitter {
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
            this.privateKey = CryptoManager_1.default.loadPrivateKey(privateKey, this.forceTcp ? 'rsa' : 'ecc');
            let cloudPublicKey = this.forceTcp
                ? CLOUD_PUBLIC_KEY_TCP
                : CLOUD_PUBLIC_KEY_UDP;
            if (this.cloud.publicKeyPEM) {
                cloudPublicKey = this.cloud.publicKeyPEM;
            }
            try {
                CryptoManager_1.default.setServerKey(cloudPublicKey, this.forceTcp ? 'rsa' : 'ecc');
            }
            catch (err) {
                throw new Error('Cloud public key error. Are you using a tcp key without calling forceTcpProtocol()?');
            }
            this.serverKey = CryptoManager_1.default.getServerKey();
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
                this.socket = node_mbed_dtls_client_1.default.connect({
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
                this.socket = new net_1.Socket();
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
                dns_1.default.resolve(host, (err, address) => {
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
                    value: Buffer.from(`${CoapUriType_1.default.Subscribe}/${eventName}`)
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
                    const hash = CryptoManager_1.default.createHmacDigest(cipherText, sessionKey);
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
                    this.decipherStream = new CryptoStream_1.default({
                        iv,
                        key,
                        streamType: 'decrypt'
                    });
                    this.cipherStream = new CryptoStream_1.default({
                        iv,
                        key,
                        streamType: 'encrypt'
                    });
                    const chunkingIn = new ChunkingStream_1.default({ outgoing: false });
                    const chunkingOut = new ChunkingStream_1.default({ outgoing: true });
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
            var e_1, _a;
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
            try {
                for (var _b = __asyncValues(this.subscriptionsMap.entries()), _c; _c = await _b.next(), !_c.done;) {
                    const sub = _c.value;
                    await delay(50);
                    this.sendSubscribe(sub[0], sub[1][0], sub[1][1], sub[1][2]);
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (_c && !_c.done && (_a = _b.return)) await _a.call(_b);
                }
                finally { if (e_1) throw e_1.error; }
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
                        const fileURL = new url_1.URL(url);
                        const protocol = fileURL.protocol === 'https:' ? https_1.default : http_1.default;
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
                        if (crc && buffer_crc32_1.default(fileBuffer).toString('hex') !== crc) {
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
            const packet = coap_packet_1.default.parse(data);
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
                case CoapUriType_1.default.GetTime: {
                    this.emit('time', parseInt(packet.payload.toString('hex'), 16));
                    break;
                }
                case CoapUriType_1.default.Describe: {
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
                case CoapUriType_1.default.Function: {
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
                case CoapUriType_1.default.Hello: {
                    clearTimeout(this.helloTimeout);
                    this.helloTimeout = null;
                    break;
                }
                case CoapUriType_1.default.PrivateEvent:
                case CoapUriType_1.default.PublicEvent: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove E or e
                    this.emitWithPrefix(uris.join('/'), packet);
                    break;
                }
                case CoapUriType_1.default.Variable: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove v
                    const varName = uris.join('/');
                    this.sendVariable(varName, packet);
                    break;
                }
                case CoapUriType_1.default.UpdateBegin:
                case CoapUriType_1.default.UpdateDone:
                case CoapUriType_1.default.UpdateReady: {
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
                case CoapUriType_1.default.Chunk: {
                    this.emit('Chunk', packet);
                    break;
                }
                case CoapUriType_1.default.FileRequest: {
                    const uris = packet.options
                        .filter(o => o.name === 'Uri-Path')
                        .map(o => o.value.toString('utf8'));
                    uris.shift(); // Remove g
                    const fileName = uris.join('/');
                    this.sendFile(fileName, packet);
                    break;
                }
                case CoapUriType_1.default.SignalStart: {
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
                        value: Buffer.from(CoapUriType_1.default.Hello)
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
                        value: Buffer.from(CoapUriType_1.default.GetTime)
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
                    const lastCrc = buffer_crc32_1.default.unsigned(chunkPacket.payload);
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
                    payload: Buffer.from(CoapUriType_1.default.UpdateReady),
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
                                { name: 'Uri-Path', value: Buffer.from(CoapUriType_1.default.Chunk) }
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
            if (buffer_crc32_1.default(fileContentBufferWithoutCrc).toString('hex') !==
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
                        payload: CoapMessages_1.default.toBinary(1, 'uint8'),
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
                    CoapMessages_1.default.toBinary(flags, 'uint8'),
                    CoapMessages_1.default.toBinary(chunkSize, 'uint16'),
                    CoapMessages_1.default.toBinary(fileSize, 'uint32'),
                    CoapMessages_1.default.toBinary(destFlag, 'uint8'),
                    CoapMessages_1.default.toBinary(destAddr, 'uint32')
                ];
                // add filename optional payloads for sending file
                if (fileName && fileName.length > 0) {
                    payloadArray.push(CoapMessages_1.default.toBinary(fileName.length, 'uint8'));
                    payloadArray.push(CoapMessages_1.default.toBinary(fileName, 'string'));
                }
                const packetBegin = {
                    code: 'POST',
                    confirmable: true,
                    messageId: this.nextMessageID(),
                    options: [
                        {
                            name: 'Uri-Path',
                            value: Buffer.from(CoapUriType_1.default.UpdateBegin)
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
                            ? buffer_crc32_1.default.unsigned(bufferChunks[chunkIndex])
                            : null;
                        // send
                        const options = [
                            {
                                name: 'Uri-Path',
                                value: Buffer.from(CoapUriType_1.default.Chunk)
                            },
                            {
                                name: 'Uri-Query',
                                value: CoapMessages_1.default.toBinary(lastCrc, 'crc')
                            },
                            {
                                name: 'Uri-Query',
                                value: CoapMessages_1.default.toBinary(chunkIndex, 'uint16')
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
                                value: Buffer.from(CoapUriType_1.default.UpdateDone)
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
                        payload: CoapMessages_1.default.toBinary(returnValue, 'int32'),
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
                        payload: CoapMessages_1.default.toBinary(variableValue, type),
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
            const packetBuffer = coap_packet_1.default.generate(packet);
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
                            ? CoapUriType_1.default.PrivateEvent
                            : CoapUriType_1.default.PublicEvent}/${name}`)
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
exports.default = new Trackle();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVHJhY2tsZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9jbGllbnQvVHJhY2tsZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7QUFBQSxnRUFBaUM7QUFDakMsOERBQXFDO0FBQ3JDLDhDQUFzQjtBQUV0QixtQ0FBc0M7QUFDdEMsZ0RBQXdCO0FBQ3hCLGtEQUEwQjtBQUMxQiw2QkFBNkI7QUFDN0Isa0ZBQXlDO0FBRXpDLDRDQUFvQjtBQUNwQiw2QkFBMEI7QUFFMUIsMkVBQW1EO0FBQ25ELHVFQUErQztBQUMvQyx5RUFBaUQ7QUFDakQsdUVBQStDO0FBQy9DLHVFQUErQztBQUUvQyxNQUFNLFdBQVcsR0FBRyxLQUFLLENBQUM7QUFDMUIsTUFBTSxxQkFBcUIsR0FBRyxFQUFFLENBQUM7QUFDakMsTUFBTSxnQkFBZ0IsR0FBRyxDQUFDLENBQUM7QUFDM0IsTUFBTSxvQkFBb0IsR0FBRyxFQUFFLENBQUM7QUFDaEMsTUFBTSxvQkFBb0IsR0FBRyxFQUFFLENBQUM7QUFDaEMsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLENBQUM7QUFFbkMsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLENBQUM7QUFDbkMsTUFBTSxjQUFjLEdBQUcsS0FBSyxDQUFDO0FBRTdCLE1BQU0sZ0JBQWdCLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztBQUNoQyxNQUFNLG9CQUFvQixHQUFHLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDcEMsTUFBTSxlQUFlLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztBQUMvQixNQUFNLFlBQVksR0FBRyxvQkFBb0IsR0FBRyxlQUFlLENBQUM7QUFFNUQsTUFBTSxVQUFVLEdBQUcsR0FBRyxDQUFDO0FBRXZCLE1BQU0sc0JBQXNCLEdBQUcsSUFBSSxDQUFDO0FBUXBDLE1BQU0saUJBQWlCLEdBQUcsbUJBQW1CLENBQUM7QUFDOUMsTUFBTSxvQkFBb0IsR0FBRzs7Ozs7Ozs7O0dBUzFCLENBQUM7QUFFSixN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