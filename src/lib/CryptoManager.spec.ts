import test from 'ava';
import CryptoManager from './CryptoManager';

// tslint:disable: no-expression-statement
test('randomBytes', t => {
  t.truthy(Buffer.isBuffer(CryptoManager.randomBytes(5)));
  t.is(CryptoManager.randomBytes(5).length, 5);
});
