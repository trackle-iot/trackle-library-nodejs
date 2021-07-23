import crypto from 'crypto';
import ECKey from 'ec-key';
import NodeRSA from 'node-rsa';
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
        const ecKey = new ECKey(keyPEM, 'pem');
        CryptoManager.serverKey = ecKey;
    }
    else {
        // tslint:disable-next-line: no-object-mutation
        CryptoManager.serverKey = new NodeRSA(keyPEM, 'pkcs8-public-pem', {
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
        });
    }
};
CryptoManager.loadPrivateKey = (key, algorithm) => {
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
CryptoManager.randomBytes = (count) => crypto.randomBytes(count);
CryptoManager.createHmacDigest = (ciphertext, sessionKey) => {
    const hmac = crypto.createHmac(HASH_TYPE, sessionKey);
    hmac.update(ciphertext);
    return hmac.digest();
};
export default CryptoManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3J5cHRvTWFuYWdlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvQ3J5cHRvTWFuYWdlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLE1BQU0sTUFBTSxRQUFRLENBQUM7QUFDNUIsT0FBTyxLQUFLLE1BQU0sUUFBUSxDQUFDO0FBQzNCLE9BQU8sT0FBTyxNQUFNLFVBQVUsQ0FBQztBQUUvQixNQUFNLFNBQVMsR0FBRyxNQUFNLENBQUM7QUFFekIsTUFBTSxhQUFhO0lBaURqQixZQUFZLFVBQW1CO1FBSXhCLFlBQU8sR0FBRyxDQUFDLE1BQWMsRUFBVSxFQUFFLENBQzFDLElBQUksQ0FBQyxVQUFVLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBSnZDLElBQUksQ0FBQyxVQUFVLEdBQUcsVUFBVSxDQUFDO0lBQy9CLENBQUM7O0FBbERhLDBCQUFZLEdBQUcsR0FBb0IsRUFBRSxDQUFDLGFBQWEsQ0FBQyxTQUFTLENBQUM7QUFDOUQsMEJBQVksR0FBRyxDQUFDLE1BQWMsRUFBRSxTQUFrQixFQUFFLEVBQUU7SUFDbEUsSUFBSSxTQUFTLElBQUksU0FBUyxLQUFLLEtBQUssRUFBRTtRQUNwQyxNQUFNLEtBQUssR0FBRyxJQUFJLEtBQUssQ0FBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFDdkMsYUFBYSxDQUFDLFNBQVMsR0FBRyxLQUFLLENBQUM7S0FDakM7U0FBTTtRQUNMLCtDQUErQztRQUMvQyxhQUFhLENBQUMsU0FBUyxHQUFHLElBQUksT0FBTyxDQUFDLE1BQU0sRUFBRSxrQkFBa0IsRUFBRTtZQUNoRSxnQkFBZ0IsRUFBRSxPQUFPO1lBQ3pCLGFBQWEsRUFBRSxPQUFPO1NBQ3ZCLENBQUMsQ0FBQztLQUNKO0FBQ0gsQ0FBQyxDQUFDO0FBQ1ksNEJBQWMsR0FBRyxDQUM3QixHQUFvQixFQUNwQixTQUFrQixFQUNELEVBQUU7SUFDbkIsSUFBSSxTQUFTLElBQUksU0FBUyxLQUFLLEtBQUssRUFBRTtRQUNwQyxPQUFPLEdBQUcsQ0FBQyxRQUFRLEVBQUUsQ0FBQyxVQUFVLENBQUMsWUFBWSxDQUFDO1lBQzVDLENBQUMsQ0FBQyxJQUFJLEtBQUssQ0FBQyxHQUFHLEVBQUUsS0FBSyxDQUFDLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQztZQUN6QyxDQUFDLENBQUMsR0FBRyxDQUFDO0tBQ1Q7SUFDRCxPQUFPLEdBQUcsQ0FBQyxRQUFRLEVBQUUsQ0FBQyxVQUFVLENBQUMsWUFBWSxDQUFDO1FBQzVDLENBQUMsQ0FBQyxJQUFJLE9BQU8sQ0FBQyxHQUFHLEVBQUUsbUJBQW1CLEVBQUU7WUFDcEMsZ0JBQWdCLEVBQUUsT0FBTztZQUN6QixhQUFhLEVBQUUsT0FBTztTQUN2QixDQUFDO1FBQ0osQ0FBQyxDQUFDLElBQUksT0FBTyxDQUFDLEdBQUcsRUFBRSxtQkFBbUIsRUFBRTtZQUNwQyxnQkFBZ0IsRUFBRSxPQUFPO1lBQ3pCLGFBQWEsRUFBRSxPQUFPO1NBQ3ZCLENBQUMsQ0FBQztBQUNULENBQUMsQ0FBQztBQUVZLHlCQUFXLEdBQUcsQ0FBQyxLQUFhLEVBQVUsRUFBRSxDQUNwRCxNQUFNLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxDQUFDO0FBRWQsOEJBQWdCLEdBQUcsQ0FDL0IsVUFBa0IsRUFDbEIsVUFBa0IsRUFDVixFQUFFO0lBQ1YsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxTQUFTLEVBQUUsVUFBVSxDQUFDLENBQUM7SUFDdEQsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUN4QixPQUFPLElBQUksQ0FBQyxNQUFNLEVBQUUsQ0FBQztBQUN2QixDQUFDLENBQUM7QUFhSixlQUFlLGFBQWEsQ0FBQyJ9