export default class CoapMessages {
  public static toBinary = (
    value: string | number | Buffer | object,
    type?: string
  ): Buffer => {
    const typeName = type || typeof value;

    if (value === null) {
      return Buffer.alloc(0);
    }

    switch (typeName) {
      case 'uint8': {
        const buffer = Buffer.allocUnsafe(1);
        buffer.writeUInt8(value as number, 0);
        return buffer;
      }
      case 'uint16': {
        const buffer = Buffer.allocUnsafe(2);
        buffer.writeUInt16BE(value as number, 0);
        return buffer;
      }
      case 'uint32':
      case 'crc': {
        const buffer = Buffer.allocUnsafe(4);
        buffer.writeUInt32BE(value as number, 0);
        return buffer;
      }

      case 'int':
      case 'int32': {
        const buffer = Buffer.allocUnsafe(4);
        buffer.writeInt32BE(value as number, 0);
        return buffer;
      }

      case 'long':
      case 'int64': {
        const buffer = Buffer.allocUnsafe(6);
        buffer.writeIntBE(value as number, 0, 6);
        return buffer;
      }

      case 'number':
      case 'double': {
        const buffer = Buffer.allocUnsafe(8);
        buffer.writeDoubleLE(value as number, 0);
        return buffer;
      }

      case 'buffer': {
        return Buffer.concat((value as unknown) as Uint8Array[]);
      }

      case 'json': {
        return Buffer.from(value.toString() || '');
      }

      case 'string':
      default: {
        return Buffer.from(value.toString() || '');
      }
    }
  };
}
