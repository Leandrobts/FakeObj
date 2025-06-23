// js/utils.mjs

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 { /* ... (código da classe como antes) ... */
    constructor(low, high) {
        this._isAdvancedInt64 = true; // Propriedade para identificação
        let buffer = new Uint32Array(2);
        
        let is_one_arg = false;
        if (arguments.length === 1) { is_one_arg = true; }
        if (arguments.length === 0) { 
            low = 0; high = 0; is_one_arg = false; 
        }

        if (!is_one_arg) {
            if (typeof (low) !== 'number' || typeof (high) !== 'number') {
                if (low instanceof AdvancedInt64 && high === undefined) {
                    buffer[0] = low.low();
                    buffer[1] = low.high();
                    this.buffer = buffer;
                    return;
                }
                throw TypeError('low/high must be numbers or single AdvancedInt64 argument');
            }
        }
        
        const check_range = (x) => Number.isInteger(x) && x >= 0 && x <= 0xFFFFFFFF;

        if (is_one_arg) {
            if (typeof (low) === 'number') {
                if (!Number.isSafeInteger(low)) { throw TypeError('number arg must be a safe integer'); }
                buffer[0] = low & 0xFFFFFFFF;
                buffer[1] = Math.floor(low / (0xFFFFFFFF + 1)); // Aproximação para high
            } else if (typeof (low) === 'string') {
                let str = low;
                let _PAIR_MATCHER;
                if (str.startsWith('0x')) { str = str.slice(2); _PAIR_MATCHER = /../g; } 
                else { _PAIR_MATCHER = /../g; } // Não mais usado diretamente

                if (str.length > 16) { throw RangeError('AdvancedInt64 string input too long'); }
                str = str.padStart(16, '0'); // Pad para 16 hex chars (8 bytes)

                const highStr = str.substring(0, 8);
                const lowStr = str.substring(8, 16);

                buffer[1] = parseInt(highStr, 16);
                buffer[0] = parseInt(lowStr, 16);

            } else if (low instanceof AdvancedInt64) { // Adicionado para construção a partir de outro AdvancedInt64
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
        if (!(other instanceof AdvancedInt64)) { return false; }
        return this.low() === other.low() && this.high() === other.high();
    }
    
    static Zero = new AdvancedInt64(0,0); // Static property

    toString(hex = false) {
        if (!hex) { // Decimal string - pode ser impreciso para números grandes
            // Para precisão, seria necessário BigInt ou uma biblioteca de bignum
            if (this.high() === 0) return String(this.low());
            return `(H:0x${this.high().toString(16)}, L:0x${this.low().toString(16)})`; // Aproximação
        }
        // Hex string
        return '0x' + this.high().toString(16).padStart(8, '0') + '_' + this.low().toString(16).padStart(8, '0');
    }
    
    toNumber() { // Pode perder precisão se o número for > 2^53 - 1
        return this.high() * (0xFFFFFFFF + 1) + this.low();
    }

    add(val) {
        if (!(val instanceof AdvancedInt64)) { 
            val = new AdvancedInt64(val); // Tenta converter se for número ou string
        }
        let low = this.low() + val.low();
        let high = this.high() + val.high() + Math.floor(low / (0xFFFFFFFF + 1));
        return new AdvancedInt64(low & 0xFFFFFFFF, high & 0xFFFFFFFF);
    }

    sub(val) {
        if (!(val instanceof AdvancedInt64)) { 
            val = new AdvancedInt64(val);
        }
        // Empresta se necessário
        let newLow = this.low() - val.low();
        let newHigh = this.high() - val.high();
        if (newLow < 0) {
            newLow += (0xFFFFFFFF + 1); // Adiciona 2^32
            newHigh -= 1; // Empresta do high
        }
        return new AdvancedInt64(newLow & 0xFFFFFFFF, newHigh & 0xFFFFFFFF);
    }
}


export function isAdvancedInt64Object(obj) {
    return obj && obj._isAdvancedInt64 === true;
}

export async function PAUSE(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function toHex(val, bits = 32) {
    if (isAdvancedInt64Object(val)) {
        return val.toString(true); // toString(true) já formata como 0x...
    }
    if (typeof val !== 'number') {
        return `NonNumeric(${typeof val}:${String(val)})`; // Melhor log para não números
    }
    if (isNaN(val)) { // Verifica explicitamente se o tipo é 'number' mas o valor é NaN
        return 'ValIsNaN'; // Log claro para NaN
    }

    let hexStr;
    if (val < 0) {
        // Para 32-bit, o comportamento padrão de (val >>> 0).toString(16) lida com isso.
        // Para outros tamanhos de bits, a conversão de complemento de dois é mais complexa.
        if (bits === 32) {
            hexStr = (val >>> 0).toString(16);
        } else if (bits === 16) {
            hexStr = ((val & 0xFFFF) >>> 0).toString(16);
        } else if (bits === 8) {
            hexStr = ((val & 0xFF) >>> 0).toString(16);
        } else { // Para bits === 64 ou outros não explicitamente tratados
            hexStr = val.toString(16); // Pode não ser o esperado para negativos grandes
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
    const charsPerAdv64 = 4; // Cada AdvancedInt64 pode armazenar 4 caracteres UTF-16 (2 bytes cada)

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
        // Garante a terminação nula se a string não preencher um AdvancedInt64 completo
        // ou se a string estiver vazia (resultando em um QWORD nulo).
        // Se o último Adv64 já tiver zeros por causa do fim da string, isso é redundante mas inofensivo.
        // Se a string for vazia, adiciona um QWORD nulo.
        if (result.length === 0 || 
            result[result.length-1].low() !==0 || result[result.length-1].high() !==0 ) {
            
            // Verifica se o último char foi nulo e se já quebrou o loop.
            // Esta lógica de terminação nula pode precisar de refinamento para cobrir todos os casos perfeitamente.
            // Se o último bloco foi parcialmente preenchido e terminou com \0, queremos esse \0.
            // Se a string terminou e não era múltiplo de 4, e o último char não era \0, precisamos de um \0.
            // A lógica atual de terminação dentro do loop já tenta lidar com isso.
            // Se a string é vazia, e queremos um QWORD nulo:
             if (str.length === 0) result.push(AdvancedInt64.Zero);

            // Se a string não preencheu o último QWORD e nullTerminate é true,
            // os zeros já foram preenchidos por charX_code = 0.
            // Um QWORD nulo explícito só é necessário se o último QWORD não for todo zero.
            // E se a string já terminou com um \0 que caiu no meio de um QWORD.
        }
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

/**
 * Reinterpreta os bits de um número de 64-bit (double) como um BigInt de 64-bit.
 * @param {number} d O número double a ser convertido.
 * @returns {BigInt} A representação BigInt dos bits do double.
 */
export function doubleToBigInt(d) {
    const buffer = new ArrayBuffer(8);
    const float64View = new Float64Array(buffer);
    const bigIntView = new BigUint64Array(buffer);
    float64View[0] = d;
    return bigIntView[0];
}

/**
 * Reinterpreta os bits de um BigInt de 64-bit como um número de 64-bit (double).
 * @param {BigInt} b O BigInt a ser convertido.
 * @returns {number} O número double correspondente aos bits do BigInt.
 */
export function bigIntToDouble(b) {
    const buffer = new ArrayBuffer(8);
    const bigIntView = new BigUint64Array(buffer);
    const float64View = new Float64Array(buffer);
    bigIntView[0] = b;
    return float64View[0];
}
