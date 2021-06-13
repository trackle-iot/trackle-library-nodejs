import crc32 from 'buffer-crc32';
import CoapPacket from 'coap-packet';
import dns from 'dns';
import ECKey from 'ec-key';
import { EventEmitter } from 'events';
import { Socket } from 'net';
import dtls from 'node-mbed-dtls-client';
import NodeRSA from 'node-rsa';
import os from 'os';

import ChunkingStream from '../lib/ChunkingStream';
import CoapMessages from '../lib/CoapMessages';
import CryptoManager from '../lib/CryptoManager';
import CryptoStream from '../lib/CryptoStream';
import CoapUriType from '../types/CoapUriType';

const COUNTER_MAX = 65536;
const EVENT_NAME_MAX_LENGTH = 64;
const FUNCTIONS_MAX_NUMBER = 10;
const VARIABLES_MAX_NUMBER = 10;
const SUBSCRIPTIONS_MAX_NUMBER = 10;

const PRODUCT_FIRMWARE_VERSION = 1;
const SOCKET_TIMEOUT = 31000;

const DESCRIBE_METRICS = 1 << 2;
const DESCRIBE_APPLICATION = 1 << 1;
const DESCRIBE_SYSTEM = 1 << 0;
const DESCRIBE_ALL = DESCRIBE_APPLICATION | DESCRIBE_SYSTEM;

const CHUNK_SIZE = 256;

const SEND_EVENT_ACK_TIMEOUT = 20000;

type DeviceState = 'next' | 'nonce' | 'set-session-key';
type EventType = 'PRIVATE' | 'PUBLIC';
type EventFlags = 'WITH_ACK' | 'NO_ACK';
type FunctionFlags = 'OWNER_ONLY';
type SubscriptionType = 'ALL_DEVICES' | 'MY_DEVICES';

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

const VERSION = process.env.npm_package_version;

export interface ICloudOptions {
  address?: string;
  publicKeyPEM?: string;
  port?: number;
}

const getPlatformID = (): number => {
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

const delay = async (ms: number): Promise<void> =>
  await new Promise(resolve => setTimeout(resolve, ms));

class Trackle extends EventEmitter {
  public cloud: ICloudOptions;

  private cipherStream: CryptoStream;
  private decipherStream: CryptoStream;
  private deviceID: Buffer;
  private forceTcp: boolean = false;
  private otaUpdateEnabled: boolean = true;
  private otaUpdatePending: boolean = false;
  private otaUpdateForced: boolean = false;
  private helloTimeout: number;
  private host: string;
  private isInitialized: boolean;
  private isConnected: boolean;
  private isConnecting: boolean;
  private isDisconnected: boolean;
  private messageID: number = 0;
  private owners: string[];
  private pingInterval: number;
  private platformID: number;
  private productFirmwareVersion: number;
  private productID: number;
  private port: number;
  private privateKey: NodeRSA | ECKey;
  private serverKey: NodeRSA | ECKey;
  private socket: Socket | dtls.Socket;
  private state: DeviceState;
  private filesMap: Map<
    string,
    [string, (fileName: string) => Buffer | Promise<Buffer>]
  >;
  private functionsMap: Map<
    string,
    [string, (args: string) => number | Promise<number>]
  >;
  private subscriptionsMap: Map<
    string,
    [(packet: CoapPacket.ParsedPacket) => void, SubscriptionType]
  >;
  private variablesMap: Map<
    string,
    [string, (varName: string) => any | Promise<any>]
  >;
  private sentPacketCounterMap: Map<number, number>;
  private wasOtaUpgradeSuccessful: boolean = false; // not used
  private keepalive: number = this.forceTcp ? 15000 : 30000;
  private claimCode: string;

  constructor(cloudOptions: ICloudOptions = {}) {
    super();

    this.filesMap = new Map<
      string,
      [string, (fileName: string) => Buffer | Promise<Buffer>]
    >();
    this.functionsMap = new Map<
      string,
      [string, (args: string) => number | Promise<number>]
    >();
    this.subscriptionsMap = new Map<
      string,
      [(packet: CoapPacket.ParsedPacket) => void, SubscriptionType]
    >();
    this.variablesMap = new Map<
      string,
      [string, (varName: string) => any | Promise<any>]
    >();

    this.cloud = cloudOptions;
  }

  public forceTcpProtocol = () => (this.forceTcp = true);

  public begin = async (
    deviceID: string,
    privateKeyPEM: string,
    productID?: number,
    productFirmwareVersion?: number,
    platformID?: number
  ) => {
    if (deviceID === '') {
      throw new Error(`You must define deviceID`);
    }
    if (deviceID.length !== 24) {
      throw new Error(`Wrong deviceID`);
    }
    this.deviceID = Buffer.from(deviceID, 'hex');

    if (privateKeyPEM === '') {
      throw new Error(`You must define privateKeyPEM`);
    }
    this.privateKey = CryptoManager.loadPrivateKey(
      privateKeyPEM,
      this.forceTcp ? 'rsa' : 'ecc'
    );

    let cloudPublicKey = this.forceTcp
      ? CLOUD_PUBLIC_KEY_TCP
      : CLOUD_PUBLIC_KEY_UDP;
    if (this.cloud.publicKeyPEM) {
      cloudPublicKey = this.cloud.publicKeyPEM;
    }
    try {
      CryptoManager.setServerKey(cloudPublicKey, this.forceTcp ? 'rsa' : 'ecc');
    } catch (err) {
      throw new Error(
        'Cloud public key error. Are you using a tcp key without calling forceTcpProtocol()?'
      );
    }
    this.serverKey = CryptoManager.getServerKey();

    if (this.cloud.address) {
      const index = this.cloud.address.indexOf('://');
      this.host =
        index >= 0 ? this.cloud.address.substr(index + 3) : this.cloud.address;
    } else {
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
      } catch (err) {
        throw new Error(
          `Could not resolve host address ${this.host}: ${err.message}`
        );
      }
    }

    this.port = this.cloud.port || (this.forceTcp ? 5683 : 5684);

    this.platformID = platformID || getPlatformID();
    this.productID = productID || COUNTER_MAX;
    this.productFirmwareVersion =
      productFirmwareVersion || PRODUCT_FIRMWARE_VERSION;

    this.isInitialized = true;
  };

  public connect = async () => {
    if (this.isConnecting) {
      return;
    }
    if (!this.isInitialized) {
      throw new Error(
        'You must initialize library calling begin before connect'
      );
    }
    this.isConnecting = true;
    this.sentPacketCounterMap = new Map<number, number>();

    if (!this.forceTcp) {
      const handshakeTimeout = setTimeout(() => {
        this.reconnect(new Error('handshake timeout'));
      }, 5000);
      this.socket = dtls.connect(
        {
          debug:
            (process.env.DEBUG_MBED &&
              parseInt(process.env.DEBUG_MBED, 10) > 0) ||
            undefined,
          host: this.host,
          key: this.privateKey.toBuffer('pkcs8'),
          peerPublicKey: this.serverKey.toBuffer('spki'),
          port: this.port
        },
        (socket: dtls.Socket) => {
          clearTimeout(handshakeTimeout);
          this.emit('connect', {
            host: this.host,
            port: this.port
          });

          socket.on('data', this.onNewCoapMessage);
          socket.on('error', (err: Error) => {
            this.reconnect(err);
          });
          socket.on('close', () =>
            this.reconnect(new Error('dtls socket close'))
          );

          this.socket = socket;
          this.decipherStream = socket;
          this.cipherStream = socket;
          this.finalizeHandshake();
        }
      );
      this.socket.on('err', (_: any, msg: string) =>
        this.reconnect(new Error(msg))
      );
    } else {
      this.state = 'nonce';
      this.socket = new Socket();
      this.socket.setTimeout(SOCKET_TIMEOUT);

      this.socket.on('data', this.onReadData);
      this.socket.on('error', this.reconnect);
      this.socket.on('close', () => this.reconnect(new Error('socket close')));
      this.socket.on('timeout', (err: any) => this.reconnect(err));

      this.socket.connect(
        {
          host: this.host,
          port: this.port
        },
        () =>
          this.emit('connect', {
            host: this.host,
            port: this.port
          })
      );
    }
  };

  public connected = (): boolean => this.isConnected;

  public setKeepalive = (keepalive: number) => {
    this.keepalive = keepalive;
  };

  public setClaimCode = (claimCode: string) => {
    this.claimCode = claimCode;
  };

  public file = (
    fileName: string,
    mimeType: string,
    retrieveFileCallback: (fileName: string) => Promise<Buffer>
  ) => {
    this.filesMap.set(fileName, [mimeType, retrieveFileCallback]);
  };

  public post = (
    name: string,
    callFunctionCallback: (args: string) => number | Promise<number>,
    functionFlags?: FunctionFlags
  ): boolean => {
    if (name.length > EVENT_NAME_MAX_LENGTH) {
      return false;
    }
    if (this.functionsMap.size >= FUNCTIONS_MAX_NUMBER) {
      return false;
    }
    this.functionsMap.set(name, [functionFlags || '', callFunctionCallback]);
    return true;
  };

  public get = (
    name: string,
    type: string,
    retrieveValueCallback: (varName: string) => any | Promise<any>
  ) => {
    if (name.length > EVENT_NAME_MAX_LENGTH) {
      return false;
    }
    if (this.variablesMap.size >= VARIABLES_MAX_NUMBER) {
      return false;
    }
    this.variablesMap.set(name, [type, retrieveValueCallback]);
    return true;
  };

  public disconnect = () => {
    this.disconnectInternal();
    this.isDisconnected = true;
    this.emit('disconnect');
  };

  public subscribe = (
    eventName: string,
    callback: (event: string, data: string) => void,
    subscriptionType?: SubscriptionType
  ): boolean => {
    if (eventName.length > EVENT_NAME_MAX_LENGTH) {
      return false;
    }
    if (this.subscriptionsMap.size >= SUBSCRIPTIONS_MAX_NUMBER) {
      return false;
    }
    const handler = (packet: CoapPacket.ParsedPacket) => {
      const uris = packet.options
        .filter(o => o.name === 'Uri-Path')
        .map(o => o.value.toString('utf8'));
      uris.shift(); // Remove E or e
      const name = uris.join('/');
      const data = packet.payload.toString('utf8');
      callback(name, data);
    };
    let type: SubscriptionType = 'ALL_DEVICES';
    if (subscriptionType && subscriptionType === 'MY_DEVICES') {
      type = 'MY_DEVICES';
    }
    this.subscriptionsMap.set(eventName, [handler, type]);
    return true;
  };

  public unsubscribe = (eventName: string) => {
    if (!this.isConnected) {
      return;
    }
    const subValue = this.subscriptionsMap.get(eventName);
    this.removeListener(eventName, subValue[0]);
  };

  public publish = async (
    eventName: string,
    data?: string,
    eventType?: EventType,
    eventFlags?: EventFlags,
    messageID?: string
  ) => {
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
    const messageSent = this.sendEvent(
      eventName,
      data,
      nextMessageID,
      confirmable,
      eventType
    );
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
          await this.listenFor(
            'ACK',
            null,
            nextMessageID,
            SEND_EVENT_ACK_TIMEOUT
          );
          this.emit('publishCompleted', { success: true, messageID });
        } catch (err) {
          this.emit('publishCompleted', { success: false, messageID });
        }
      }
    }
  };

  public enableUpdates = () => {
    if (!this.otaUpdateEnabled) {
      this.otaUpdateEnabled = true;
      if (this.isConnected) {
        this.publish('iotready/device/updates/enabled', 'true', 'PRIVATE');
      }
    }
  };

  public disableUpdates = () => {
    if (this.otaUpdateEnabled) {
      this.otaUpdateEnabled = false;
      if (this.isConnected) {
        this.publish('iotready/device/updates/enabled', 'false', 'PRIVATE');
      }
    }
  };

  public updatesEnabled = (): boolean => this.otaUpdateEnabled;

  public updatesPending = (): boolean => this.otaUpdatePending;

  private getDiagnostic = (): Buffer => Buffer.concat([Buffer.alloc(1, 0)]);

  private getDescription = (): Buffer => {
    const filesObject = {};
    Array.from(this.filesMap.keys()).forEach((key: string) => {
      filesObject[key] = this.filesMap.get(key);
    });
    const functions = Array.from(this.functionsMap.keys());
    const variablesObject = {};
    Array.from(this.variablesMap.keys()).forEach((key: string) => {
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

  private resolvePromise = (host: string): Promise<string[]> => {
    return new Promise((resolve, reject) => {
      dns.resolve(host, (err, address) => {
        if (err) reject(err);
        resolve(address);
      });
    });
  };

  private emitWithPrefix = (
    eventName: string,
    packet: CoapPacket.ParsedPacket
  ) =>
    this.eventNames()
      .filter((eventNamePrefix: string): boolean =>
        eventName.startsWith(eventNamePrefix)
      )
      .forEach((eventNamePrefix: string): boolean =>
        this.emit(eventNamePrefix, packet)
      );

  private sendSubscribe = async (
    eventName: string,
    handler: (packet: CoapPacket.ParsedPacket) => void,
    subscriptionType: SubscriptionType
  ) => {
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
      options
    };

    this.writeCoapData(packet);
    try {
      await this.listenFor('ACK', null, messageID, SEND_EVENT_ACK_TIMEOUT);
      this.emit('subscribe', eventName);
    } catch (err) {
      this.emit('error', new Error('Subscribe: ' + err.message));
    }
  };

  private disconnectInternal = () => {
    if (this.isDisconnected) {
      return;
    }

    this.isConnecting = false;
    this.isConnected = false;
    this.state = 'nonce';
    if (this.decipherStream) {
      this.decipherStream.removeAllListeners();
    }

    this.socket.removeAllListeners();
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }

    this.subscriptionsMap.forEach(
      (
        value: [(packet: CoapPacket.ParsedPacket) => void, SubscriptionType],
        eventName: string
      ) => {
        this.removeListener(eventName, value[0]);
      }
    );

    if (this.pingInterval) {
      clearInterval(this.pingInterval as any);
      this.pingInterval = null;
    }
  };

  private reconnect = (error: NodeJS.ErrnoException): void => {
    if (this.isDisconnected) {
      return;
    }
    if (error !== undefined) {
      if (error.code === 'ENOTFOUND') {
        this.emit(
          'connectionError',
          new Error('No server found at this address!')
        );
        if (this.socket) {
          this.socket.destroy();
        }
      } else if (error.code === 'ECONNREFUSED') {
        this.emit(
          'connectionError',
          new Error('Connection refused! Please check the IP.')
        );
        if (this.socket) {
          this.socket.destroy();
        }
      } else {
        this.emit('connectionError', new Error(error.message));
      }
    }

    this.disconnectInternal();
    setTimeout(() => {
      this.emit('reconnect');
      this.connect();
    }, 5000);
  };

  private onReadData = (data: Buffer): void => {
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

  private finalizeHandshake = async () => {
    this.sendHello(this.wasOtaUpgradeSuccessful);

    if (this.forceTcp) {
      this.helloTimeout = setTimeout(
        () =>
          this.reconnect(new Error('Did not get hello response in 2 seconds')),
        2000
      ) as any;
    }

    this.state = 'next';

    // Ping every 15 or 30 seconds
    this.pingInterval = setInterval(
      () => this.pingServer(),
      this.keepalive
    ) as any;
    this.isConnected = true;
    this.emit('connected');

    this.subscribe('iotready', this.handleSystemEvent);

    for await (const sub of this.subscriptionsMap.entries()) {
      await delay(50);
      this.sendSubscribe(sub[0], sub[1][0], sub[1][1]);
    }

    // send getTime
    await delay(50);
    this.sendTimeRequest();

    // claimCode
    if (
      this.claimCode &&
      this.claimCode.length > 0 &&
      this.claimCode.length < 70
    ) {
      await delay(50);
      this.publish('iotready/device/claim/code', this.claimCode, 'PRIVATE');
    }

    await delay(50);
    if (this.otaUpdateEnabled) {
      this.publish('iotready/device/updates/enabled', 'true', 'PRIVATE');
    } else {
      this.publish('iotready/device/updates/enabled', 'false', 'PRIVATE');
    }
    await delay(50);
    if (this.otaUpdateForced) {
      this.publish('iotready/device/updates/forced', 'true', 'PRIVATE');
    } else {
      this.publish('iotready/device/updates/forced', 'false', 'PRIVATE');
    }
  };

  private handleSystemEvent = async (
    eventName: string,
    data: string
  ): Promise<void> => {
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
          this.publish(
            'iotready/device/updates/forced',
            newUpdateForcedData.toString(),
            'PRIVATE'
          );
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

  private onNewCoapMessage = async (data: Buffer): Promise<void> => {
    const packet = CoapPacket.parse(data);
    if (packet.ack) {
      this.emit('COMPLETE', packet);
    }

    if (packet.code === '0.00' && packet.ack) {
      this.emit('ACK', packet);
    }

    if (packet.code === '0.00' && packet.confirmable) {
      this.sendPingAck(packet);
    }

    if (packet.code === '2.05' && packet.ack) {
      // get time response
      this.emit('time', parseInt(packet.payload.toString('hex'), 16));
    }

    const uriOption = packet.options.find(option => option.name === 'Uri-Path');
    if (!uriOption) {
      return;
    }
    const coapPath = uriOption.value.toString('utf8');
    const messageType =
      coapPath.substring(0, coapPath.indexOf('/')) || coapPath;

    switch (messageType) {
      case CoapUriType.Describe: {
        const uriQuery = packet.options.find(
          option => option.name === 'Uri-Query'
        );
        const descriptionFlags = parseInt(uriQuery.value.toString('hex'), 16);
        if (
          descriptionFlags === DESCRIBE_ALL ||
          descriptionFlags === DESCRIBE_METRICS
        ) {
          this.sendDescribe(descriptionFlags, packet);
        } else {
          this.emit(
            'error',
            new Error(`Invalid DESCRIBE flags ${descriptionFlags}`)
          );
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
        clearTimeout(this.helloTimeout as any);
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
        } else if (packet.code === '0.03') {
          this.emit('UpdateDone', packet);
        } else if (packet.code === '2.04') {
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
        uris.shift(); // Remove v
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
        this.emit(
          'error',
          new Error(`Coap URI ${coapPath} is not supported: ${packet}`)
        );
      }
    }
  };

  private prepareDevicePublicKey = (nonce: Buffer): Buffer =>
    // Concat a bunch of data that we will send over encrypted with the
    // server public key.
    Buffer.concat([
      nonce,
      this.deviceID,
      this.privateKey.exportKey('pkcs8-public-der')
    ]);

  private nextMessageID = (): number => {
    this.messageID += 1;
    if (this.messageID >= COUNTER_MAX) {
      this.messageID = 0;
    }

    return this.messageID;
  };

  private sendHello = (wasOtaUpgradeSuccessful?: boolean) => {
    const HELLO_FLAG_OTA_UPGRADE_SUCCESSFUL = 1;
    const HELLO_FLAG_DIAGNOSTICS_SUPPORT = 2;
    const HELLO_FLAG_IMMEDIATE_UPDATES_SUPPORT = 4;

    let flags = wasOtaUpgradeSuccessful ? HELLO_FLAG_OTA_UPGRADE_SUCCESSFUL : 0;
    flags |= HELLO_FLAG_DIAGNOSTICS_SUPPORT;
    flags |= HELLO_FLAG_IMMEDIATE_UPDATES_SUPPORT;

    const data = [
      this.productID >> 8,
      this.productID & 0xff,
      this.productFirmwareVersion >> 8,
      this.productFirmwareVersion & 0xff,
      0, // Reserved flag
      flags, // Flags -- newly upgraded. We probably won't use this
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

  private sendTimeRequest = () => {
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

  private sendDescribe = async (
    descriptionFlags: number,
    serverPacket: CoapPacket.ParsedPacket
  ) => {
    const payload =
      descriptionFlags === DESCRIBE_ALL
        ? this.getDescription()
        : this.getDiagnostic();
    const packet = {
      ack: true,
      code: '2.05', // Content
      messageId: this.messageID, // not next
      payload,
      token: serverPacket.token
    };

    this.writeCoapData(packet);
  };

  private sendSignalStartReturn = async (
    serverPacket: CoapPacket.ParsedPacket
  ) => {
    const packet = {
      ack: true,
      code: '2.04', // Changed
      messageId: this.nextMessageID(),
      token: serverPacket.token
    };

    this.writeCoapData(packet);
  };

  private sendPingAck = async (serverPacket: CoapPacket.ParsedPacket) => {
    const packet = {
      ack: true,
      code: '0.00', // Empty
      messageId: serverPacket.messageId
    };

    this.writeCoapData(packet);
  };

  private receiveFile = async (packet: CoapPacket.ParsedPacket) => {
    // 1- get file info
    let chunksSize = packet.payload.readUInt16BE(1);
    if (!chunksSize || chunksSize === 0) {
      chunksSize = CHUNK_SIZE;
    }
    const fileSize = packet.payload.readInt32BE(3);
    const fileNameLength = packet.payload[12];
    const fileName = packet.payload.toString('utf8', 13, 13 + fileNameLength);
    /******************************/

    if (
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
    }

    if (packet.payload.length === 12 || this.filesMap.has(fileName)) {
      // 2- listen Chunk packet and fill fileContentBuffer
      const fileContentBuffer = Buffer.allocUnsafe(fileSize);
      const chunksNumber = Math.floor((fileSize + chunksSize - 1) / chunksSize);
      let chunksCounter = 0;
      const chunkMissedArray = [];
      const chunkHandler = (chunkPacket: CoapPacket.ParsedPacket) => {
        const chunkPacketOption = chunkPacket.options.filter(
          (option: { name: any; value: Buffer }): boolean =>
            option.name === 'Uri-Query'
        );
        const chunkCrc = chunkPacketOption[0].value.readUInt32BE(0);
        const lastCrc = crc32.unsigned(chunkPacket.payload);
        const chunkNumber = chunkPacketOption[1].value.readUInt16BE(0);
        if (chunkCrc === lastCrc) {
          chunksCounter += 1;
          let chunkLength = chunksSize;
          if (fileSize - chunksSize * chunkNumber < chunksSize) {
            chunkLength = fileSize - chunksSize * chunkNumber;
          }
          chunkPacket.payload.copy(
            fileContentBuffer,
            chunksSize * chunkNumber,
            0,
            chunkLength
          );
        } else {
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
          } else {
            // check if is a valid firmware file
            try {
              const fileBuffer = this.validateFirmwareFile(fileContentBuffer);
              this.emit('otaReceived', {
                fileContentBuffer: fileBuffer,
                fileSize
              });
            } catch (err) {
              this.emit('error', err);
            }
          }
        }
      };
      this.on('Chunk', chunkHandler);
      /******************************/

      // 3- send UpdateReady packet in order to start receiving chunks
      const responsePacket = {
        code: '2.04', // Changed
        confirmable: false,
        messageId: this.nextMessageID(),
        payload: Buffer.from(CoapUriType.UpdateReady),
        token: packet.token
      };
      this.writeCoapData(responsePacket);
      /******************************/

      // 4- wait for UpdateDone packet
      const updateDoneHandler = (updateDonePacket: CoapPacket.ParsedPacket) => {
        if (chunksNumber !== chunksCounter && chunkMissedArray.length > 0) {
          // send UpdateDoneAckError
          const updateDoneAckErrorPacket = {
            ack: true,
            code: '4.00', // Bad request
            confirmable: false,
            messageId: this.nextMessageID(),
            token: updateDonePacket.token
          };
          this.writeCoapData(updateDoneAckErrorPacket);

          // in fast OTA send only 1 ChunkMissed with messageIds array
          const chunkMissedBuffer = Buffer.allocUnsafe(
            2 * chunkMissedArray.length
          );
          for (let i = 0; i < chunkMissedArray.length; i += 1) {
            chunkMissedBuffer.writeUInt16BE(chunkMissedArray[i], i * 2);
          }
          const chunkMissedPacket = {
            code: 'GET', // Changed
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
        } else {
          // send UpdateDoneAck
          const updateDoneAckPacket = {
            ack: true,
            code: '2.04', // Changed
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
    } else {
      // send UpdateAbort packet
      const responsePacket = {
        code: '4', // Bad Request
        confirmable: false,
        messageId: this.nextMessageID(),
        payload: Buffer.from('26'),
        token: packet.token
      };
      this.writeCoapData(responsePacket);

      this.emit('error', new Error(`File ${fileName} not found`));
    }
  };

  private validateFirmwareFile = (fileContentBuffer: Buffer): Buffer => {
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
  };

  private sendFile = async (
    fileName: string,
    serverPacket: CoapPacket.ParsedPacket
  ) => {
    if (!this.isConnected) {
      return;
    }

    if (this.filesMap.has(fileName)) {
      const [, receiveFileCallback] = this.filesMap.get(fileName);
      let fileBuffer: Buffer;
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
      } catch (err) {
        if (fileBuffer) {
          this.messageID -= 1;
        }
        this.writeError(serverPacket, err.message, err.status || '4.00');
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
        let i: number = 0;
        while (i < fileSize) {
          const buffer = fileBuffer.slice(i, (i += chunkSize));
          bufferChunks.push(buffer);
        }

        // send each chunk
        let chunkIndex: number;
        for (
          chunkIndex = 0;
          chunkIndex < bufferChunks.length;
          chunkIndex += 1
        ) {
          const buffer = Buffer.alloc(chunkSize);
          bufferChunks[chunkIndex].copy(
            buffer,
            0,
            0,
            bufferChunks[chunkIndex].length
          );
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
    } else {
      this.writeError(serverPacket, `File ${fileName} not found`, '4.04');
      this.emit('error', new Error(`File ${fileName} not found`));
    }
  };

  private listenFor = async (
    eventName: string,
    token?: number,
    messageId?: number,
    timeoutMs?: number
  ): Promise<any> => {
    const tokenHex = token ? Buffer.from([token]).toString('hex') : null;
    return new Promise(
      (
        resolve: (packet: CoapPacket.ParsedPacket) => void,
        reject: (error?: Error) => void
      ) => {
        const timeout = setTimeout(() => {
          cleanUpListeners();
          reject(new Error(`Request timed out ${eventName}`));
        }, timeoutMs || this.keepalive * 2);

        // adds a one time event
        const handler = (packet: CoapPacket.ParsedPacket) => {
          clearTimeout(timeout);

          const packetTokenHex = packet.token.toString('hex');
          if (tokenHex && tokenHex !== packetTokenHex) {
            // 'Tokens did not match'
            return;
          }

          if (
            messageId &&
            (messageId !== packet.messageId || parseFloat(packet.code) >= 4)
          ) {
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
      }
    );
  };

  private pingServer = () => {
    if (!this.isConnected) {
      return;
    }

    const packet = {
      code: '0',
      confirmable: true,
      messageId: this.nextMessageID()
    };

    this.writeCoapData(packet);
  };

  private writeError = (
    serverPacket: CoapPacket.ParsedPacket,
    message: string,
    responseCode: string
  ) => {
    const packet = {
      ack: true,
      code: responseCode,
      confirmable: false,
      messageId: serverPacket.messageId,
      payload: Buffer.from(message)
    };

    this.writeCoapData(packet);
  };

  private sendFunctionResult = async (
    functionName: string,
    args: string,
    caller: string,
    serverPacket: CoapPacket.ParsedPacket
  ) => {
    if (!this.isConnected) {
      return;
    }

    if (args.length > 622) {
      this.writeError(serverPacket, 'Args max length is 622 bytes', '4.00');
      this.emit('error', new Error('Args max length is 622 bytes'));
      return;
    }

    if (this.functionsMap.has(functionName)) {
      const [functionFlags, callFunctionCallback] = this.functionsMap.get(
        functionName
      );
      if (
        functionFlags === 'OWNER_ONLY' &&
        (!this.owners || !this.owners.includes(caller))
      ) {
        this.writeError(
          serverPacket,
          'Forbidden: only owners can call this function',
          '4.03'
        );
        this.emit('error', new Error('Forbidden'));
        return;
      }

      let returnValue: number;
      try {
        returnValue = await callFunctionCallback(args);
        const packet = {
          code: '2.04',
          messageId: this.nextMessageID(),
          payload: CoapMessages.toBinary(returnValue, 'int32'),
          token: serverPacket.token
        };
        this.writeCoapData(packet);
      } catch (err) {
        if (returnValue) {
          this.messageID -= 1;
        }
        this.writeError(serverPacket, err.message, err.status || '4.00');
        this.emit('error', new Error(err.message));
      }
    } else {
      this.writeError(
        serverPacket,
        `Function ${functionName} not found`,
        '4.04'
      );
      this.emit('error', new Error(`Function ${functionName} not found`));
    }
  };

  private sendVariable = async (
    varName: string,
    serverPacket: CoapPacket.ParsedPacket
  ) => {
    if (!this.isConnected) {
      return;
    }

    let hasName = varName;
    if (varName.indexOf('/') >= -1) {
      hasName = varName.split('/')[0];
    }
    if (this.variablesMap.has(hasName)) {
      const [type, retrieveValueCallback] = this.variablesMap.get(hasName);
      let variableValue: any;
      try {
        variableValue = await retrieveValueCallback(varName);
        if (
          (type === 'string' || type === 'json') &&
          JSON.stringify(variableValue).length > 622
        ) {
          this.writeError(
            serverPacket,
            'Value max length is 622 bytes',
            '4.00'
          );
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
      } catch (err) {
        if (variableValue) {
          this.messageID -= 1;
        }
        this.writeError(serverPacket, err.message, err.status || '4.00');
        this.emit('error', new Error(err.message));
      }
    } else {
      this.writeError(serverPacket, `Variable ${varName} not found`, '4.04');
      this.emit('error', new Error(`Variable ${varName} not found`));
    }
  };

  private writeCoapData = (packet: CoapPacket.Packet): boolean => {
    if (packet.confirmable) {
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
    }
    const packetBuffer = CoapPacket.generate(packet);
    return this.writeData(packetBuffer);
  };

  private writeData = (packet: Buffer): boolean => {
    try {
      if (this.socket) {
        return this.cipherStream.write(packet);
      }
      return false;
    } catch (ignore) {
      this.emit('error', new Error(`Write data error: ${ignore}`));
      return false;
    }
  };

  private sendEvent = (
    name: string,
    data: string,
    nextMessageID: number,
    confirmable: boolean,
    eventType?: EventType
  ): boolean => {
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
          value: Buffer.from(
            `${
              eventType && eventType === 'PRIVATE'
                ? CoapUriType.PrivateEvent
                : CoapUriType.PublicEvent
            }/${name}`
          )
        }
      ],
      payload
    };

    return this.writeCoapData(packet);
  };
}

export default new Trackle();
