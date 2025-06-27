// js/utils.mjs

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 {
    constructor(low, high) {
        this._isAdvancedInt64 = true;
        let buffer = new Uint32Array(2);

        let is_one_arg = false;
        if (arguments.length === 1) { is_one_arg = true; }
        if (arguments.length === 0) {
            low = 0; high = 0; is_one_arg = false;
        }

        const check_range = (x) => Number.isInteger(x) && x >= 0 && x <= 0xFFFFFFFF;

        if (is_one_arg) {
            if (typeof (low) === 'number') {
                if (!Number.isFinite(low)) {
                    throw new TypeError("Single number argument for AdvancedInt64 must be a finite number.");
                }
                buffer[0] = low >>> 0;
                buffer[1] = (low / (0xFFFFFFFF + 1)) >>> 0;
            } else if (typeof (low) === 'string') {
                let str = low;
                if (str.startsWith('0x')) { str = str.slice(2); }

                if (str.length > 16) { throw RangeError('AdvancedInt64 string input too long'); }
                str = str.padStart(16, '0');

                const highStr = str.substring(0, 8);
                const lowStr = str.substring(8, 16);

                buffer[1] = parseInt(highStr, 16);
                buffer[0] = parseInt(lowStr, 16);

            } else if (low instanceof AdvancedInt64) {
                 buffer[0] = low.low();
                 buffer[1] = low.high();
            } else {
                throw TypeError('single arg must be number, hex string or AdvancedInt64');
            }
        } else { // two args
            if (!check_range(low) || !check_range(high)) {
                throw RangeError('low/high must be uint32 numbers');
            }
            buffer[0] = low;
            buffer[1] = high;
        }
        this.buffer = buffer;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    equals(other) {
        if (!isAdvancedInt64Object(other)) { return false; }
        return this.low() === other.low() && this.high() === other.high();
    }

    lessThanOrEqual(other) {
        if (!isAdvancedInt64Object(other)) {
            throw new TypeError("Comparison target must be an AdvancedInt64 object.");
        }
        if (this.high() < other.high()) {
            return true;
        }
        if (this.high() === other.high()) {
            return this.low() <= other.low();
        }
        return false;
    }

    greaterThanOrEqual(other) {
        if (!isAdvancedInt64Object(other)) {
            throw new TypeError("Comparison target must be an AdvancedInt64 object.");
        }
        if (this.high() > other.high()) {
            return true;
        }
        if (this.high() === other.high()) {
            return this.low() >= other.low();
        }
        return false;
    }

    lessThan(other) {
        if (!isAdvancedInt64Object(other)) {
            throw new TypeError("Comparison target must be an AdvancedInt64 object.");
        }
        if (this.high() < other.high()) {
            return true;
        }
        if (this.high() === other.high()) {
            return this.low() < other.low();
        }
        return false;
    }

    static Zero = new AdvancedInt64(0,0);
    static NaNValue = new AdvancedInt64(0, 0x7ff80000);

    toString(hex = false) {
        if (!hex) {
            if (this.high() === 0) return String(this.low());
            return `(H:0x${this.high().toString(16)}, L:0x${this.low().toString(16)})`;
        }
        return '0x' + this.high().toString(16).padStart(8, '0') + '_' + this.low().toString(16).padStart(8, '0');
    }

    toNumber() {
        return this.high() * (0xFFFFFFFF + 1) + this.low();
    }

    add(val) {
        let otherInt64;
        if (!isAdvancedInt64Object(val)) {
            if (typeof val === 'number' && Number.isFinite(val)) {
                otherInt64 = new AdvancedInt64(val);
            } else {
                throw TypeError(`Argument for add must be a finite number or AdvancedInt64. Got: ${typeof val} ${val}`);
            }
        } else {
            otherInt64 = val;
        }

        let low = this.low() + otherInt64.low();
        let high = this.high() + otherInt64.high();

        if (low > 0xFFFFFFFF) {
            high += Math.floor(low / (0xFFFFFFFF + 1));
            low = low & 0xFFFFFFFF;
        }

        return new AdvancedInt64(low >>> 0, high >>> 0);
    }

    sub(val) {
        let otherInt64;
        if (!isAdvancedInt64Object(val)) {
            if (typeof val === 'number' && Number.isFinite(val)) {
                otherInt64 = new AdvancedInt64(val);
            } else {
                throw TypeError(`Argument for sub must be a finite number or AdvancedInt64. Got: ${typeof val} ${val}`);
            }
        } else {
            otherInt64 = val;
        }

        let newLow = this.low() - otherInt64.low();
        let newHigh = this.high() - otherInt64.high();

        if (newLow < 0) {
            newLow += (0xFFFFFFFF + 1);
            newHigh -= 1;
        }

        return new AdvancedInt64(newLow >>> 0, newHigh >>> 0);
    }
}


export function isAdvancedInt64Object(obj) {
    return obj && obj._isAdvancedInt64 === true;
}

export const PAUSE = async (ms) => {
    return new Promise(resolve => setTimeout(resolve, ms));
};

// Global reference for the log function, to be set by the main orchestrator
let _globalLogFunction = console.log; // Default to console.log

export function setLogFunction(fn) {
    _globalLogFunction = fn;
}

export function log(message, type = 'info', funcName = '') {
    if (_globalLogFunction) {
        _globalLogFunction(message, type, funcName);
    } else {
        console.log(`[LOG_UNSET] ${message}`);
    }
}


export function toHex(val, bits = 32) {
    if (isAdvancedInt64Object(val)) {
        return val.toString(true);
    }
    if (typeof val !== 'number') {
        return `NonNumeric(${typeof val}:${String(val)})`;
    }
    if (isNaN(val)) {
        return 'ValIsNaN';
    }

    let hexStr;
    if (val < 0) {
        if (bits === 32) {
            hexStr = (val >>> 0).toString(16);
        } else if (bits === 16) {
            hexStr = ((val & 0xFFFF) >>> 0).toString(16);
        } else if (bits === 8) {
            hexStr = ((val & 0xFF) >>> 0).toString(16);
        } else {
            hexStr = val.toString(16);
        }
    } else {
        hexStr = val.toString(16);
    }

    const numChars = Math.ceil(bits / 4);
    return '0x' + hexStr.padStart(numChars, '0');
}

export function stringToAdvancedInt64Array(str, nullTerminate = true) {
    if (typeof str !== 'string') {
        console.error("Input to stringToAdvancedInt64Array must be a string.");
        return [];
    }
    const result = [];
    const charsPerAdv64 = 4;

    for (let i = 0; i < str.length; i += charsPerAdv64) {
        let low = 0;
        let high = 0;

        const char1_code = str.charCodeAt(i);
        const char2_code = (i + 1 < str.length) ? str.charCodeAt(i + 1) : 0;
        const char3_code = (i + 2 < str.length) ? str.charCodeAt(i + 2) : 0;
        const char4_code = (i + 3 < str.length) ? str.charCodeAt(i + 3) : 0;

        low = (char2_code << 16) | char1_code;
        high = (char4_code << 16) | char3_code;

        result.push(new AdvancedInt64(low, high));

        if (char4_code === 0 && i + 3 < str.length && nullTerminate) break;
        if (char3_code === 0 && i + 2 < str.length && char4_code === 0 && nullTerminate) break;
        if (char2_code === 0 && i + 1 < str.length && char3_code === 0 && char4_code === 0 && nullTerminate) break;

    }
    if (nullTerminate && (str.length % charsPerAdv64 !== 0 || str.length === 0)) {
        if (str.length === 0) result.push(AdvancedInt64.Zero);
    }
    return result;
}

export function advancedInt64ArrayToString(arr) {
    let str = "";
    if (!Array.isArray(arr)) return "InputIsNotArray";

    for (const adv64 of arr) {
        if (!isAdvancedInt64Object(adv64)) continue;

        const low = adv64.low();
        const high = adv64.high();

        const char1_code = low & 0xFFFF;
        const char2_code = (low >>> 16) & 0xFFFF;
        const char3_code = high & 0xFFFF;
        const char4_code = (high >>> 16) & 0xFFFF;

        if (char1_code === 0) break;
        str += String.fromCharCode(char1_code);
        if (char2_code === 0) break;
        str += String.fromCharCode(char2_code);
        if (char3_code === 0) break;
        str += String.fromCharCode(char3_code);
        if (char4_code === 0) break;
        str += String.fromCharCode(char4_code);
    }
    return str;
}

export function doubleToBigInt(d) {
    const buffer = new ArrayBuffer(8);
    const float64View = new Float64Array(buffer);
    const bigIntView = new BigUint64Array(buffer);
    float64View[0] = d;
    return bigIntView[0];
}

export function bigIntToDouble(b) {
    const buffer = new ArrayBuffer(8);
    const bigIntView = new BigUint64Array(buffer);
    const float64View = new Float64Array(buffer);
    bigIntView[0] = b;
    return float64View[0];
}
