
export * from './lib/ber/index.js'
import {
    ASN1,
    InvalidAsn1Error,
    Reader,
    Writer
} from './lib/ber/index.js'

export const Ber = {
    ...ASN1,
    InvalidAsn1Error,
    Reader,
    Writer
};
export const BerReader = Reader
export const BerWriter = Writer
