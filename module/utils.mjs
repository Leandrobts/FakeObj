//utils.mjs

import { Int } from './int64.mjs'; // Importa Int para manipulação de 64 bits

// Classe de erro customizada para "die" (parada fatal com mensagem).
export class DieError extends Error {
    constructor(...args) {
        super(...args);
        this.name = this.constructor.name; // Define o nome do erro.
    }
}

// Lança um erro fatal com uma mensagem.
export function die(msg = '') {
    throw new DieError(msg);
}

// Acessa o elemento 'console' do DOM para logs.
const console = document.getElementById('output-advanced'); // Usando 'output-advanced' conforme seu main.mjs

// Função de log adaptada para usar o elemento DOM ou fallback.
let _globalLogFunction = console.append; // Default para o método append do elemento.

export function setLogFunction(fn) {
    _globalLogFunction = fn; // Permite definir uma função de log externa.
}

export function log(message, type = 'info', funcName = '') {
    if (_globalLogFunction) {
        // Formato original do seu log em main.mjs
        const outputDiv = document.getElementById('output-advanced'); // Re-obtem o elemento para garantir
        if (outputDiv) {
            const timestamp = `[${new Date().toLocaleTimeString()}]`;
            const prefix = funcName ? `[${funcName}] ` : '';
            const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
            const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool', 'debug'].includes(type) ? type : 'info';

            if (outputDiv.innerHTML.length > 600000) {
                const lastPart = outputDiv.innerHTML.substring(outputDiv.innerHTML.length - 300000);
                outputDiv.innerHTML = `<span class="log-info">[${new Date().toLocaleTimeString()}] [Log Truncado...]</span>\n` + lastPart;
            }
            outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${sanitizedMessage}\n</span>`;
            outputDiv.scrollTop = outputDiv.scrollHeight;
        } else {
            console.log(`[LOG_UNSET] ${message}`); // Fallback se o elemento não for encontrado.
        }
    } else {
        console.log(`[LOG_UNSET] ${message}`); // Fallback se a função de log não estiver definida.
    }
}


export function clear_log() {
    // Limpa o conteúdo do console no DOM.
    if (document.getElementById('output-advanced')) {
        document.getElementById('output-advanced').innerHTML = '';
    } else {
        console.log("Output div not found to clear log.");
    }
}

// Alinha um endereço a um determinado alinhamento (potência de 2).
export function align(a, alignment) {
    if (!(a instanceof Int)) { // Converte para Int se não for.
        a = new Int(a);
    }
    const mask = -alignment & 0xffffffff; // Máscara para alinhamento.
    let type = a.constructor; // Mantém o tipo original (Int ou Addr).
    let low = a.lo & mask; // Alinha a parte low.
    return new type(low, a.hi); // Retorna um novo objeto com o endereço alinhado.
}

// Envia um buffer como um arquivo para uma URL.
export async function send(url, buffer, file_name, onload = () => {}) {
    const file = new File(
        [buffer],
        file_name,
        { type: 'application/octet-stream' }
    );
    const form = new FormData();
    form.append('upload', file);

    log('send');
    const response = await fetch(url, { method: 'POST', body: form });

    if (!response.ok) {
        throw Error(`Network response was not OK, status: ${response.status}`);
    }
    onload();
}

// Pausa a execução por um determinado número de milissegundos.
// Usado principalmente para ceder ao GC e permitir atualizações do DOM.
export function sleep(ms = 0) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Converte um número para sua representação hexadecimal com prefixo '0x'.
export function hex(number) {
    return '0x' + number.toString(16);
}

// Converte um número para sua representação hexadecimal sem prefixo '0x'.
export function hex_np(number) {
    return number.toString(16);
}

// Gera um hexdump de um array de bytes.
export function hexdump(view) {
    const num_16 = view.length & ~15;
    const residue = view.length - num_16;
    const max_off_len = hex_np(((view.length + 7) & ~7) - 1).length;

    function chr(i) {
        if (0x20 <= i && i <= 0x7e) {
            return String.fromCodePoint(i);
        }
        return '.';
    }

    function to_hex(view, offset, length) {
        return (
            [...view.slice(offset, offset + length)]
            .map(e => hex_np(e).padStart(2, '0'))
            .join(' ')
        );
    }

    let bytes = [];
    for (let i = 0; i < num_16; i += 16) {
        const long1 = to_hex(view, i, 8);
        const long2 = to_hex(view, i + 8, 8);

        let print = '';
        for (let j = 0; j < 16; j++) {
            print += chr(view[j]);
        }

        bytes.push([`${long1}  ${long2}`, print]);
    }

    if (residue) {
        const small = residue <= 8;
        const long1_len = small ? residue : 8;

        let long1 = to_hex(view, num_16, long1_len);
        if (small) {
            for (let i = 0; i < 8 - residue; i++) {
                long1 += ' xx';
            }
        }

        const long2 = (() => {
            if (small) {
                return Array(8).fill('xx').join(' ');
            }

            let res = to_hex(view, num_16 + 8, residue - 8);
            for (let i = 0; i < 16 - residue; i++) {
                res += ' xx';
            }

            return res;
        })();

        let print = '';
        for (let i = 0; i < residue; i++) {
            print += chr(view[num_16 + i]);
        }
        for (let i = 0; i < 16 - residue; i++) {
            print += ' ';
        }

        bytes.push([`${long1}  ${long2}`, print]);
    }

    for (const [pos, [val, print]] of bytes.entries()) {
        const off = hex_np(pos * 16).padStart(max_off_len, '0');
        log(`${off} | ${val} |${print}|`);
    }
}

// Converte um buffer de bytes para uma string JavaScript.
export function jstr(buffer) {
    let res = '';
    for (const item of buffer) {
        if (item === 0) { // Para no primeiro byte nulo.
            break;
        }
        res += String.fromCodePoint(item);
    }
    return String(res); // Converte para string primitiva.
}


// --- Funções de log do seu exploit original (mantidas e adaptadas para o novo sistema) ---

// Esta função agora é basicamente um wrapper para a nova função 'log' do PSFree.
export const toHex = (val, bits = 32) => {
    if (val && val._isAdvancedInt64 === true) { // Se for seu AdvancedInt64
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
};

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
        if (!adv64 || !adv64._isAdvancedInt64) continue; // Verifica se é um AdvancedInt64 válido

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
