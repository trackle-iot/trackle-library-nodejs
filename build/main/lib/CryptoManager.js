"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const ec_key_1 = __importDefault(require("ec-key"));
const node_rsa_1 = __importDefault(require("node-rsa"));
const HASH_TYPE = 'sha1';
class CryptoManager {
    constructor(privateKey) {
        this.encrypt = (buffer) => this.privateKey.encryptPrivate(buffer);
        this.privateKey = privateKey;
    }
}
CryptoManager.getServerKey = () => CryptoManager.serverKey;
CryptoManager.setServerKey = (keyPEM, algorithm) => {
    if (algorithm && algorithm === 'ecc') {
        const ecKey = new ec_key_1.default(keyPEM, 'pem');
        CryptoManager.serverKey = ecKey;
    }
    else {
        // tslint:disable-next-line: no-object-mutation
        CryptoManager.serverKey = new node_rsa_1.default(keyPEM, 'pkcs8-public-pem', {
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
        });
    }
};
CryptoManager.loadPrivateKey = (key, algorithm) => {
    if (algorithm && algorithm === 'ecc') {
        return key.toString().startsWith('-----BEGIN')
            ? new ec_key_1.default(key, 'pem').toBuffer('pkcs8')
            : key;
    }
    return key.toString().startsWith('-----BEGIN')
        ? new node_rsa_1.default(key, 'pkcs1-private-pem', {
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
        })
        : new node_rsa_1.default(key, 'pkcs1-private-der', {
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
        });
};
CryptoManager.randomBytes = (count) => crypto_1.default.randomBytes(count);
CryptoManager.createHmacDigest = (ciphertext, sessionKey) => {
    const hmac = crypto_1.default.createHmac(HASH_TYPE, sessionKey);
    hmac.update(ciphertext);
    return hmac.digest();
};
exports.default = CryptoManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3J5cHRvTWFuYWdlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvQ3J5cHRvTWFuYWdlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLG9EQUE0QjtBQUM1QixvREFBMkI7QUFDM0Isd0RBQStCO0FBRS9CLE1BQU0sU0FBUyxHQUFHLE1BQU0sQ0FBQztBQUV6QixNQUFNLGFBQWE7SUFpRGpCLFlBQVksVUFBbUI7UUFJeEIsWUFBTyxHQUFHLENBQUMsTUFBYyxFQUFVLEVBQUUsQ0FDMUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxjQUFjLENBQUMsTUFBTSxDQUFDLENBQUM7UUFKdkMsSUFBSSxDQUFDLFVBQVUsR0FBRyxVQUFVLENBQUM7SUFDL0IsQ0FBQzs7QUFsRGEsMEJBQVksR0FBRyxHQUFvQixFQUFFLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQztBQUM5RCwwQkFBWSxHQUFHLENBQUMsTUFBYyxFQUFFLFNBQWtCLEVBQUUsRUFBRTtJQUNsRSxJQUFJLFNBQVMsSUFBSSxTQUFTLEtBQUssS0FBSyxFQUFFO1FBQ3BDLE1BQU0sS0FBSyxHQUFHLElBQUksZ0JBQUssQ0FBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFDdkMsYUFBYSxDQUFDLFNBQVMsR0FBRyxLQUFLLENBQUM7S0FDakM7U0FBTTtRQUNMLCtDQUErQztRQUMvQyxhQUFhLENBQUMsU0FBUyxHQUFHLElBQUksa0JBQU8sQ0FBQyxNQUFNLEVBQUUsa0JBQWtCLEVBQUU7WUFDaEUsZ0JBQWdCLEVBQUUsT0FBTztZQUN6QixhQUFhLEVBQUUsT0FBTztTQUN2QixDQUFDLENBQUM7S0FDSjtBQUNILENBQUMsQ0FBQztBQUNZLDRCQUFjLEdBQUcsQ0FDN0IsR0FBb0IsRUFDcEIsU0FBa0IsRUFDRCxFQUFFO0lBQ25CLElBQUksU0FBUyxJQUFJLFNBQVMsS0FBSyxLQUFLLEVBQUU7UUFDcEMsT0FBTyxHQUFHLENBQUMsUUFBUSxFQUFFLENBQUMsVUFBVSxDQUFDLFlBQVksQ0FBQztZQUM1QyxDQUFDLENBQUMsSUFBSSxnQkFBSyxDQUFDLEdBQUcsRUFBRSxLQUFLLENBQUMsQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDO1lBQ3pDLENBQUMsQ0FBQyxHQUFHLENBQUM7S0FDVDtJQUNELE9BQU8sR0FBRyxDQUFDLFFBQVEsRUFBRSxDQUFDLFVBQVUsQ0FBQyxZQUFZLENBQUM7UUFDNUMsQ0FBQyxDQUFDLElBQUksa0JBQU8sQ0FBQyxHQUFHLEVBQUUsbUJBQW1CLEVBQUU7WUFDcEMsZ0JBQWdCLEVBQUUsT0FBTztZQUN6QixhQUFhLEVBQUUsT0FBTztTQUN2QixDQUFDO1FBQ0osQ0FBQyxDQUFDLElBQUksa0JBQU8sQ0FBQyxHQUFHLEVBQUUsbUJBQW1CLEVBQUU7WUFDcEMsZ0JBQWdCLEVBQUUsT0FBTztZQUN6QixhQUFhLEVBQUUsT0FBTztTQUN2QixDQUFDLENBQUM7QUFDVCxDQUFDLENBQUM7QUFFWSx5QkFBVyxHQUFHLENBQUMsS0FBYSxFQUFVLEVBQUUsQ0FDcEQsZ0JBQU0sQ0FBQyxXQUFXLENBQUMsS0FBSyxDQUFDLENBQUM7QUFFZCw4QkFBZ0IsR0FBRyxDQUMvQixVQUFrQixFQUNsQixVQUFrQixFQUNWLEVBQUU7SUFDVixNQUFNLElBQUksR0FBRyxnQkFBTSxDQUFDLFVBQVUsQ0FBQyxTQUFTLEVBQUUsVUFBVSxDQUFDLENBQUM7SUFDdEQsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUN4QixPQUFPLElBQUksQ0FBQyxNQUFNLEVBQUUsQ0FBQztBQUN2QixDQUFDLENBQUM7QUFhSixrQkFBZSxhQUFhLENBQUMifQ==