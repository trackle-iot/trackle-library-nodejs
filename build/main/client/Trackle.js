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
const net_1 = require("net");
const node_mbed_dtls_client_1 = __importDefault(require("node-mbed-dtls-client"));
const os_1 = __importDefault(require("os"));
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
const CHUNK_SIZE = 256;
const SEND_EVENT_ACK_TIMEOUT = 5000;
const CLOUD_ADDRESS_TCP = 'device.iotready.it';
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
const CLOUD_ADDRESS_UDP = 'udp.device.iotready.it';
const CLOUD_PUBLIC_KEY_UDP = `-----BEGIN PUBLIC KEY-----\n
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKxmdyfKwLdHxffAr0ezRV9Z0Udec\n
CeFwQ0pbwkDASWc0yKT4tPf7tNA/zK8fqi4ddoLPOhoLQjgUbVRCBdxNJw==\n
-----END PUBLIC KEY-----\n
\n`;
const VERSION = '1.1.2';
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
        this.keepalive = this.forceTcp ? 15000 : 30000;
        this.forceTcpProtocol = () => (this.forceTcp = true);
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
                    this.publish('iotready/device/updates/enabled', 'true', 'PRIVATE');
                }
            }
        };
        this.disableUpdates = () => {
            if (this.otaUpdateEnabled) {
                this.otaUpdateEnabled = false;
                if (this.isConnected) {
                    this.publish('iotready/device/updates/enabled', 'false', 'PRIVATE');
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
            this.subscribe('iotready', this.handleSystemEvent);
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
                this.publish('iotready/device/claim/code', this.claimCode, 'PRIVATE');
            }
            await delay(50);
            if (this.otaUpdateEnabled) {
                this.publish('iotready/device/updates/enabled', 'true', 'PRIVATE');
            }
            else {
                this.publish('iotready/device/updates/enabled', 'false', 'PRIVATE');
            }
            await delay(50);
            if (this.otaUpdateForced) {
                this.publish('iotready/device/updates/forced', 'true', 'PRIVATE');
            }
            else {
                this.publish('iotready/device/updates/forced', 'false', 'PRIVATE');
            }
        };
        this.handleSystemEvent = async (eventName, data) => {
            switch (eventName) {
                case 'iotready/device/reset':
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
                case 'iotready/device/updates/forced':
                    const newUpdateForcedData = data === 'true';
                    if (this.otaUpdateForced !== newUpdateForcedData) {
                        this.otaUpdateForced = newUpdateForcedData;
                        this.emit('firmwareUpdateForced', newUpdateForcedData);
                        this.publish('iotready/device/updates/forced', newUpdateForcedData.toString(), 'PRIVATE');
                    }
                    break;
                case 'iotready/device/updates/pending':
                    const newUpdatePendingData = data === 'true';
                    if (this.otaUpdatePending !== newUpdatePendingData) {
                        this.otaUpdatePending = newUpdatePendingData;
                        if (newUpdatePendingData) {
                            // true
                            this.emit('firmwareUpdatePending');
                            this.publish('iotready/device/updates/pending', '', 'PRIVATE');
                        }
                    }
                    break;
                case 'iotready/device/owners':
                    this.owners = data.split(',');
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
                            // check if is a valid firmware file
                            try {
                                const fileBuffer = this.validateFirmwareFile(fileContentBuffer);
                                this.emit('otaReceived', {
                                    fileContentBuffer: fileBuffer,
                                    fileSize
                                });
                            }
                            catch (err) {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVHJhY2tsZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9jbGllbnQvVHJhY2tsZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7QUFBQSxnRUFBaUM7QUFDakMsOERBQXFDO0FBQ3JDLDhDQUFzQjtBQUV0QixtQ0FBc0M7QUFDdEMsNkJBQTZCO0FBQzdCLGtGQUF5QztBQUV6Qyw0Q0FBb0I7QUFFcEIsMkVBQW1EO0FBQ25ELHVFQUErQztBQUMvQyx5RUFBaUQ7QUFDakQsdUVBQStDO0FBQy9DLHVFQUErQztBQUUvQyxNQUFNLFdBQVcsR0FBRyxLQUFLLENBQUM7QUFDMUIsTUFBTSxxQkFBcUIsR0FBRyxFQUFFLENBQUM7QUFDakMsTUFBTSxnQkFBZ0IsR0FBRyxDQUFDLENBQUM7QUFDM0IsTUFBTSxvQkFBb0IsR0FBRyxFQUFFLENBQUM7QUFDaEMsTUFBTSxvQkFBb0IsR0FBRyxFQUFFLENBQUM7QUFDaEMsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLENBQUM7QUFFbkMsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLENBQUM7QUFDbkMsTUFBTSxjQUFjLEdBQUcsS0FBSyxDQUFDO0FBRTdCLE1BQU0sZ0JBQWdCLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztBQUNoQyxNQUFNLG9CQUFvQixHQUFHLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDcEMsTUFBTSxlQUFlLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztBQUMvQixNQUFNLFlBQVksR0FBRyxvQkFBb0IsR0FBRyxlQUFlLENBQUM7QUFFNUQsTUFBTSxVQUFVLEdBQUcsR0FBRyxDQUFDO0FBRXZCLE1BQU0sc0JBQXNCLEdBQUcsSUFBSSxDQUFDO0FBUXBDLE1BQU0saUJBQWlCLEdBQUcsb0JBQW9CLENBQUM7QUFDL0MsTUFBTSxvQkFBb0IsR0FBRzs7Ozs7Ozs7O0dBUzFCLENBQUM7QUFFSixNQUFNLGlCQUFpQixHQUFHLHdCQUF3QixDQUFDO0FBQ25ELE1BQU0s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