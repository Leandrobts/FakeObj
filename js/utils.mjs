// js/utils.mjs

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 { // Certifique-se que a classe está exportada
    constructor(low, high) {
        this._isAdvancedInt64 = true;
        let buffer = new Uint32Array(2);
        let bytes = new Uint8Array(buffer.buffer);

        if (arguments.length > 2) { throw TypeError('AdvancedInt64 takes at most 2 args'); }
        if (arguments.length === 0) { throw TypeError('AdvancedInt64 takes at min 1 args'); }
        let is_one = false;
        if (arguments.length === 1) { is_one = true; }

        if (!is_one) {
            if (typeof (low) !== 'number' && typeof (high) !== 'number') {
                throw TypeError('low/high must be numbers');
            }
        }
        const check_range = (x) => (-0x80000000 <= x) && (x <= 0xffffffff);

        if (typeof low === 'number') {
            if (!check_range(low)) { throw TypeError('low not a valid value: ' + low); }
            if (is_one) {
                high = 0;
                if (low < 0) { high = -1; }
            } else {
                if (!check_range(high)) { throw TypeError('high not a valid value: ' + high); }
            }
            buffer[0] = low;
            buffer[1] = high;
        } else if (typeof low === 'string') {
            let hexstr = low;
            if (hexstr.substring(0, 2) === "0x") { hexstr = hexstr.substring(2); }
            if (hexstr.length % 2 === 1) { hexstr = '0' + hexstr; }
            if (hexstr.length > 16) { hexstr = hexstr.substring(hexstr.length - 16); }
            else { hexstr = hexstr.padStart(16, '0');}

            for (let i = 0; i < 8; i++) {
                bytes[i] = parseInt(hexstr.slice(14 - i*2, 16 - i*2), 16);
            }
        } else if (typeof low === 'object') {
            if (low instanceof AdvancedInt64 || (low && low._isAdvancedInt64 === true)) {
                bytes.set(low.bytes);
            } else if (low.length === 8) { // Assuming byte array
                bytes.set(low);
            } else { throw TypeError("Array must have exactly 8 elements."); }
        } else {
            throw TypeError('AdvancedInt64 does not support your object for conversion');
        }

        this.buffer = buffer;
        this.bytes = bytes;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    toString(is_pretty) {
        let lowStr = (this.low() >>> 0).toString(16).padStart(8, '0');
        let highStr = (this.high() >>> 0).toString(16).padStart(8, '0');
        if (is_pretty) {
            highStr = highStr.substring(0, 4) + '_' + highStr.substring(4);
            lowStr = lowStr.substring(0, 4) + '_' + lowStr.substring(4);
            return '0x' + highStr + '_' + lowStr;
        }
        return '0x' + highStr + lowStr;
    }
    add(other) {
        if (!isAdvancedInt64Object(other)) { other = new AdvancedInt64(other); }
        let newLow = (this.low() + other.low()) >>> 0;
        let carry = (this.low() & 0xFFFFFFFF) + (other.low() & 0xFFFFFFFF) > 0xFFFFFFFF ? 1 : 0;
        let newHigh = (this.high() + other.high() + carry) >>> 0;
        return new AdvancedInt64(newLow, newHigh);
    }
    sub(other) {
        if (!isAdvancedInt64Object(other)) { other = new AdvancedInt64(other); }
        const negOther = other.neg();
        return this.add(negOther);
    }
    neg() {
        const low = ~this.low();
        const high = ~this.high();
        const one = new AdvancedInt64(1,0);
        const res = new AdvancedInt64(low, high);
        return res.add(one);
    }
    equals(other) {
        if (!isAdvancedInt64Object(other)) {
             try { other = new AdvancedInt64(other); } catch (e) { return false; }
        }
        return this.low() === other.low() && this.high() === other.high();
    }

    static Zero = new AdvancedInt64(0,0);
    static One = new AdvancedInt64(1,0);

    static fromNumber(num) {
        if (typeof num !== 'number' || !Number.isFinite(num)) {
            throw new TypeError("AdvancedInt64.fromNumber espera um número finito.");
        }
        // Clamp to safe integer range if you want to avoid precision loss for very large JS numbers,
        // but for typical exploit dev numbers (like addresses), this direct conversion is often what's intended.
        const high = Math.floor(num / Math.pow(2, 32));
        const low = num % Math.pow(2, 32);
        return new AdvancedInt64(low, high);
    }
}

// Certifique-se que a função está exportada
export function isAdvancedInt64Object(obj) {
    return obj instanceof AdvancedInt64 || (obj && obj._isAdvancedInt64 === true);
}

export const readWriteUtils = {
    readBytes: (u8_view, offset, size) => { /* ... */ },
    // ... (resto de readWriteUtils)
};

export const generalUtils = {
    align: (addrOrInt, alignment) => { /* ... */ },
    // ... (resto de generalUtils)
};

export const jscOffsets = { // Este pode ser obsoleto/conflitante com config.mjs, mas certifique-se que não causa problemas de exportação
    js_butterfly: 0x8,
    // ... (outros offsets)
};

// Certifique-se que PAUSE está exportada
export const PAUSE = (ms = 50) => new Promise(r => setTimeout(r, ms));

// Certifique-se que toHex está exportada
export const toHex = (val, bits = 32) => {
    if (val === null || val === undefined) return 'null/undef';
    if (typeof val === 'string') return val; // Se já for string, retorna como está (ex: "N/A")
    if (typeof val !== 'number' || !isFinite(val)) return 'NaN/Invalid';
    let num = Number(val);
    if (bits <= 32 && num >= 0) { // Para DWORDS positivos, mantenha como está se for para ser interpretado como ID
        // No entanto, para consistência de endereços e valores grandes, a conversão para unsigned é melhor
         num = num >>> 0;
    } else if (bits <=32 && num < 0) { // Para DWORDS negativos (raro em offsets, mais comum em return values)
        num = num >>> 0; // Converte para unsigned int32
    }
    // Para QWORDS ou valores que precisam ser totalmente hex, a lógica abaixo é boa.
    const pad = Math.ceil(bits / 4);
    return '0x' + num.toString(16).toUpperCase().padStart(pad, '0');
};
