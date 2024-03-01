
import assert from 'node:assert';
import {ASN1} from './types.js';
import {InvalidAsn1Error} from './errors.js';

export type WriterOptions = {
    size: number;
	growthFactor: number;
}

const DEFAULT_OPTS: WriterOptions = {
	size: 1024,
	growthFactor: 8
};

///--- API

export class Writer
{
    private _buf: Buffer;
    private _size: number;
    _offset: number;
    private readonly _options: WriterOptions;
    private readonly _seq: Array<number>;

    constructor (options?: WriterOptions) {
        const opts = {...DEFAULT_OPTS, ...options};

        this._buf = Buffer.alloc(opts.size || 1024);
        this._size = this._buf.length;
        this._offset = 0;
        this._options = opts;

        // A list of offsets in the buffer where we need to insert
        // sequence tag/len pairs.
        this._seq = [];
    }

    get buffer (): Buffer {
		if (this._seq.length)
			throw new InvalidAsn1Error(this._seq.length + ' unended sequence(s)');

		return (this._buf.subarray(0, this._offset));
	}

    writeByte (b: number): void {
        if (typeof(b) !== 'number')
            throw new TypeError('argument must be a Number');

        this._ensure(1);
        this._buf[this._offset++] = b;
    }

    writeInt (i: number, tag?: number): void {
        if (!Number.isInteger(i))
            throw new TypeError('argument must be an integer');
        if (typeof(tag) !== 'number')
            tag = ASN1.Integer;

        let bytes = [];
        while (i < -0x80 || i >= 0x80) {
            bytes.push(i & 0xff);
            i = Math.floor(i / 0x100);
        }
        bytes.push(i & 0xff);

        this._ensure(2 + bytes.length);
        this._buf[this._offset++] = tag;
        this._buf[this._offset++] = bytes.length;

        while (bytes.length) {
            this._buf[this._offset++] = bytes.pop()!;
        }
    }

    writeNull (): void {
        this.writeByte(ASN1.Null);
        this.writeByte(0x00);
    }

    writeEnumeration (i: number, tag?: number): void {
        if (typeof(i) !== 'number')
            throw new TypeError('argument must be a Number');
        if (typeof(tag) !== 'number')
            tag = ASN1.Enumeration;

        return this.writeInt(i, tag);
    }

    writeBoolean (b: boolean, tag?: number) {
        if (typeof(b) !== 'boolean')
            throw new TypeError('argument must be a Boolean');
        if (typeof(tag) !== 'number')
            tag = ASN1.Boolean;

        this._ensure(3);
        this._buf[this._offset++] = tag;
        this._buf[this._offset++] = 0x01;
        this._buf[this._offset++] = b ? 0xff : 0x00;
    }

    writeString (s: string, tag?: number): void {
        if (typeof(s) !== 'string')
            throw new TypeError('argument must be a string (was: ' + typeof(s) + ')');
        if (typeof(tag) !== 'number')
            tag = ASN1.OctetString;

        const len = Buffer.byteLength(s);
        this.writeByte(tag);
        this.writeLength(len);
        if (len) {
            this._ensure(len);
            this._buf.write(s, this._offset);
            this._offset += len;
        }
    }

    writeBuffer (buf: Buffer, tag?: number): void {
        if (!Buffer.isBuffer(buf))
            throw new TypeError('argument must be a buffer');

        // If no tag is specified we will assume `buf` already contains tag and length
        if (typeof(tag) === 'number') {
            this.writeByte(tag);
            this.writeLength(buf.length);
        }

        if ( buf.length > 0 ) {
            this._ensure(buf.length);
            buf.copy(this._buf, this._offset, 0, buf.length);
            this._offset += buf.length;
        }
    }

    writeStringArray (strings: Array<string>, tag: number): void {
        if (! (strings instanceof Array))
            throw new TypeError('argument must be an Array[String]');

        const self = this;
        strings.forEach(function(s) {
            self.writeString(s, tag);
        });
    }

    // This is really to solve DER cases, but whatever for now
    writeOID (s: string, tag?: number): void {
        if (typeof(s) !== 'string')
            throw new TypeError('argument must be a string');
        if (typeof(tag) !== 'number')
            tag = ASN1.OID;

        if (!/^([0-9]+\.){0,}[0-9]+$/.test(s))
            throw new Error('argument is not a valid OID string');

        function encodeOctet(bytes: Array<number>, octet: number): void {
            if (octet < 128) {
                    bytes.push(octet);
            } else if (octet < 16384) {
                    bytes.push((octet >>> 7) | 0x80);
                    bytes.push(octet & 0x7F);
            } else if (octet < 2097152) {
                bytes.push((octet >>> 14) | 0x80);
                bytes.push(((octet >>> 7) | 0x80) & 0xFF);
                bytes.push(octet & 0x7F);
            } else if (octet < 268435456) {
                bytes.push((octet >>> 21) | 0x80);
                bytes.push(((octet >>> 14) | 0x80) & 0xFF);
                bytes.push(((octet >>> 7) | 0x80) & 0xFF);
                bytes.push(octet & 0x7F);
            } else {
                bytes.push(((octet >>> 28) | 0x80) & 0xFF);
                bytes.push(((octet >>> 21) | 0x80) & 0xFF);
                bytes.push(((octet >>> 14) | 0x80) & 0xFF);
                bytes.push(((octet >>> 7) | 0x80) & 0xFF);
                bytes.push(octet & 0x7F);
            }
        }

        const tmp = s.split('.');
        const bytes: Array<number> = [];
        bytes.push(parseInt(tmp[0]!, 10) * 40 + parseInt(tmp[1]!, 10));
        tmp.slice(2).forEach(function(b) {
            encodeOctet(bytes, parseInt(b, 10));
        });

        const self = this;
        this._ensure(2 + bytes.length);
        this.writeByte(tag);
        this.writeLength(bytes.length);
        bytes.forEach(function(b) {
            self.writeByte(b);
        });
    }


    writeLength (len: number): void {
        if (typeof(len) !== 'number')
            throw new TypeError('argument must be a Number');

        this._ensure(4);

        if (len <= 0x7f) {
            this._buf[this._offset++] = len;
        } else if (len <= 0xff) {
            this._buf[this._offset++] = 0x81;
            this._buf[this._offset++] = len;
        } else if (len <= 0xffff) {
            this._buf[this._offset++] = 0x82;
            this._buf[this._offset++] = len >> 8;
            this._buf[this._offset++] = len;
        } else if (len <= 0xffffff) {
            this._buf[this._offset++] = 0x83;
            this._buf[this._offset++] = len >> 16;
            this._buf[this._offset++] = len >> 8;
            this._buf[this._offset++] = len;
        } else {
            throw new InvalidAsn1Error('Length too long (> 4 bytes)');
        }
    }

    startSequence (tag?: number): void {
        if (typeof(tag) !== 'number')
            tag = ASN1.Sequence | ASN1.Constructor;

        this.writeByte(tag);
        this._seq.push(this._offset);
        this._ensure(3);
        this._offset += 3;
    }

    endSequence (): void {
        const seq = this._seq.pop()!;
        const start = seq + 3;
        const len = this._offset - start;

        if (len <= 0x7f) {
            this._shift(start, len, -2);
            this._buf[seq] = len;
        } else if (len <= 0xff) {
            this._shift(start, len, -1);
            this._buf[seq] = 0x81;
            this._buf[seq + 1] = len;
        } else if (len <= 0xffff) {
            this._buf[seq] = 0x82;
            this._buf[seq + 1] = len >> 8;
            this._buf[seq + 2] = len;
        } else if (len <= 0xffffff) {
            this._shift(start, len, 1);
            this._buf[seq] = 0x83;
            this._buf[seq + 1] = len >> 16;
            this._buf[seq + 2] = len >> 8;
            this._buf[seq + 3] = len;
        } else {
            throw new InvalidAsn1Error('Sequence too long');
        }
    }

    private _shift (start: number, len: number, shift: number): void {
        assert.ok(start !== undefined);
        assert.ok(len !== undefined);
        assert.ok(shift);

        this._buf.copy(this._buf, start + shift, start, start + len);
        this._offset += shift;
    }

    private _ensure (len: number): void {
        assert.ok(len);

        if (this._size - this._offset < len) {
            let sz = this._size * this._options.growthFactor;
            if (sz - this._offset < len)
                sz += len;

            const buf = Buffer.alloc(sz);

            this._buf.copy(buf, 0, 0, this._offset);
            this._buf = buf;
            this._size = sz;
        }
    }
}
