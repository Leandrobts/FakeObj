//view.mjs

import { Int, lohi_from_one } from './int64.mjs'; // Importa Int e lohi_from_one para manipulação de 64 bits
import { Addr } from './mem.mjs'; // Importa Addr para representação de endereços de memória
import { BufferView } from './rw.mjs'; // Importa BufferView para operações de leitura/escrita em blocos

import * as config from '../config.mjs'; // Importa configurações do exploit
import * as mt from './memtools.mjs'; // Importa funções de ferramentas de memória

// O construtor das classes View sempre obterá a propriedade 'buffer'
// para garantir que o JSArrayBufferView seja um WastefulTypedArray.
// Isso evita que 'm_vector' possa mudar se 'm_mode' for menor que WastefulTypedArray,
// tornando possível o cache do campo 'm_view'.
// Assim, os usuários não precisam se preocupar se o 'm_view' obtido por 'addr()'
// está potencialmente obsoleto.
// Subclasses de TypedArray ainda são implementadas como um JSArrayBufferView,
// então 'get_view_vector()' ainda funciona nelas.
function ViewMixin(superclass) {
    const res = class extends superclass {
        constructor(...args) {
            super(...args);
            this.buffer; // Garante que o TypedArray seja um WastefulTypedArray
        }

        get addr() {
            let res = this._addr_cache; // Tenta usar o cache
            if (res !== undefined) {
                return res;
            }
            res = mt.get_view_vector(this); // Obtém o endereço real do buffer da view
            this._addr_cache = res; // Armazena em cache
            return res;
        }

        get size() {
            return this.byteLength; // Retorna o tamanho em bytes
        }

        addr_at(index) {
            const size = this.BYTES_PER_ELEMENT; // Tamanho em bytes de cada elemento
            return this.addr.add(index * size); // Calcula o endereço de um elemento específico
        }

        sget(index) {
            return this[index] | 0; // Retorna o valor do elemento como um inteiro assinado de 32 bits
        }
    };

    // Solução alternativa para versões afetadas conhecidas: PS4 [6.00, 10.00)
    // A implementação de 'from()' e 'of()' em WebKit/Source/JavaScriptCore/builtins/TypedArrayConstructor.js
    // falha quando 'this' não é um dos TypedArrays embutidos.
    // Isso é uma violação da especificação ECMAScript da época.
    if (config.target >= 0x600 && config.target < 0x1000) {
        res.from = function from(...args) {
            const base = this.__proto__;
            return new this(base.from(...args).buffer);
        };

        res.of = function of(...args) {
            const base = this.__proto__;
            return new this(base.of(...args).buffer);
        };
    }

    return res;
}

// Classes View para diferentes tamanhos de elementos, estendendo TypedArrays e o ViewMixin
export class View1 extends ViewMixin(Uint8Array) {}
export class View2 extends ViewMixin(Uint16Array) {}
export class View4 extends ViewMixin(Uint32Array) {}

// Classe Buffer: Estende BufferView para operações de leitura/escrita arbitrária de bytes
export class Buffer extends BufferView {
    get addr() {
        let res = this._addr_cache;
        if (res !== undefined) {
            return res;
        }
        res = mt.get_view_vector(this);
        this._addr_cache = res;
        return res;
    }

    get size() {
        return this.byteLength;
    }

    addr_at(index) {
        return this.addr.add(index);
    }
}
// Solução alternativa para 'from()' e 'of()' para a classe Buffer
if (config.target >= 0x600 && config.target < 0x1000) {
    Buffer.from = function from(...args) {
        const base = this.__proto__;
        return new this(base.from(...args).buffer);
    };
    Buffer.of = function of(...args) {
        const base = this.__proto__;
        return new this(base.of(...args).buffer);
    };
}

// Mixin para variáveis que representam valores numéricos simples (Byte, Short, Word)
const VariableMixin = superclass => class extends superclass {
    constructor(value = 0) {
        if (typeof value !== 'number') {
            throw TypeError('value not a number');
        }
        super([value]);
    }

    addr_at(...args) {
        throw TypeError('unimplemented method'); // Este método não deve ser chamado para variáveis singulares
    }

    [Symbol.toPrimitive](hint) {
        return this[0]; // Permite coerção para tipo primitivo (o valor numérico)
    }

    toString(...args) {
        return this[0].toString(...args); // Usa o toString do número subjacente
    }
};

export class Byte extends VariableMixin(View1) {} // Valor de 1 byte
export class Short extends VariableMixin(View2) {} // Valor de 2 bytes
export class Word extends VariableMixin(View4) {} // Valor de 4 bytes (Int já é usado por int64.mjs)

// Classe LongArray: Representa um array de inteiros de 64 bits.
export class LongArray {
    constructor(length) {
        this.buffer = new DataView(new ArrayBuffer(length * 8)); // Buffer para armazenar os Int64
    }

    get addr() {
        return mt.get_view_vector(this.buffer); // Endereço do buffer subjacente
    }

    addr_at(index) {
        return this.addr.add(index * 8); // Endereço de um elemento específico
    }

    get length() {
        return this.buffer.byteLength / 8; // Número de elementos Int64
    }

    get size() {
        return this.buffer.byteLength; // Tamanho total em bytes
    }

    get byteLength() {
        return this.size; // Alias para size
    }

    get(index) {
        const buffer = this.buffer;
        const base = index * 8;
        return new Int(
            buffer.getUint32(base, true),
            buffer.getUint32(base + 4, true),
        );
    }

    set(index, value) {
        const buffer = this.buffer;
        const base = index * 8;
        const values = lohi_from_one(value); // Converte o valor para [low, high]

        buffer.setUint32(base, values[0], true);
        buffer.setUint32(base + 4, values[1], true);
    }
}

// Mixin para valores mutáveis de 64 bits (Long, Pointer)
// Usa campos privados de Int (como _u32) para mutabilidade.
const Word64Mixin = superclass => class extends superclass {
    constructor(...args) {
        if (!args.length) { // Se não houver argumentos, inicializa com 0.
            return super(0);
        }
        super(...args);
    }

    get addr() {
        // Assume que é seguro cachear. Obtém o endereço do buffer interno do Uint32Array.
        return mt.get_view_vector(this._u32);
    }

    get length() {
        return 1;
    }

    get size() {
        return 8;
    }

    get byteLength() {
        return 8;
    }

    // Não há setters para 'top' e 'bot', pois 'low'/'high' podem aceitar inteiros negativos.

    get lo() {
        return super.lo;
    }

    set lo(value) {
        this._u32[0] = value;
    }

    get hi() {
        return super.hi;
    }

    set hi(value) {
        this._u32[1] = value;
    }

    set(value) {
        const buffer = this._u32;
        const values = lohi_from_one(value); // Converte o valor para [low, high]

        buffer[0] = values[0];
        buffer[1] = values[1];
    }
};

// Classe Long: Representa um inteiro de 64 bits mutável.
export class Long extends Word64Mixin(Int) {
    as_addr() {
        return new Addr(this); // Converte o Long para um Addr
    }
}
// Classe Pointer: Estende Addr e Word64Mixin para representar ponteiros mutáveis de 64 bits.
export class Pointer extends Word64Mixin(Addr) {}
