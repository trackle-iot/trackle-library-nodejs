import crypto from 'crypto';
import ECKey from 'ec-key';
import NodeRSA from 'node-rsa';

const HASH_TYPE = 'sha1';

class CryptoManager {
  public static getServerKey = (): ECKey | NodeRSA => CryptoManager.serverKey;
  public static setServerKey = (keyPEM: string, algorithm?: string) => {
    if (algorithm && algorithm === 'ecc') {
      const ecKey = new ECKey(keyPEM, 'pem');
      CryptoManager.serverKey = ecKey;
    } else {
      // tslint:disable-next-line: no-object-mutation
      CryptoManager.serverKey = new NodeRSA(keyPEM, 'pkcs8-public-pem', {
        encryptionScheme: 'pkcs1',
        signingScheme: 'pkcs1'
      });
    }
  };
  public static loadPrivateKey = (
    key: string | Buffer,
    algorithm?: string
  ): ECKey | NodeRSA => {
    if (algorithm && algorithm === 'ecc') {
      return key.toString().startsWith('-----BEGIN')
        ? new ECKey(key, 'pem').toBuffer('pkcs8')
        : key;
    }
    return key.toString().startsWith('-----BEGIN')
      ? new NodeRSA(key, 'pkcs1-private-pem', {
          encryptionScheme: 'pkcs1',
          signingScheme: 'pkcs1'
        })
      : new NodeRSA(key, 'pkcs1-private-der', {
          encryptionScheme: 'pkcs1',
          signingScheme: 'pkcs1'
        });
  };

  public static randomBytes = (count: number): Buffer =>
    crypto.randomBytes(count);

  public static createHmacDigest = (
    ciphertext: Buffer,
    sessionKey: Buffer
  ): Buffer => {
    const hmac = crypto.createHmac(HASH_TYPE, sessionKey);
    hmac.update(ciphertext);
    return hmac.digest();
  };

  private static serverKey: NodeRSA;
  private privateKey: NodeRSA;

  constructor(privateKey: NodeRSA) {
    this.privateKey = privateKey;
  }

  public encrypt = (buffer: Buffer): Buffer =>
    this.privateKey.encryptPrivate(buffer);
}

export default CryptoManager;
