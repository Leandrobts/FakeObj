//module/int64.mjs
const isInteger = Number.isInteger;

function check_not_in_range(x) {
    // Verifica se x não é um inteiro de 32 bits assinado ou unsigned
    return !(isInteger(x) && -0x80000000 <= x && x <= 0xffffffff);
}

// Converte um valor (número ou instância de Int) para um array [low, high] de 32 bits sem sinal.
// Usado para operações onde apenas os bits low/high são necessários, evitando a criação completa de um objeto Int.
export function lohi_from_one(low) {
    if (low instanceof Int) { // Se já for uma instância de Int, retorna seus valores low/high.
        return low._u32.slice();
    }

    if (check_not_in_range(low)) { // Valida se o número está dentro do range de 32 bits.
        throw TypeError(`low not a 32-bit integer: ${low}`);
    }

    // Retorna o valor como 32 bits sem sinal (low) e a parte high (0 para positivos, -1 para negativos).
    return [low >>> 0, low < 0 ? -1 >>> 0 : 0];
}

// Classe Int: Representa um inteiro imutável de 64 bits.
// Armazena o valor em um Uint32Array de 2 elementos ([low, high]).
export class Int {
    constructor(low, high) {
        if (high === undefined) { // Construtor com um único argumento (valor completo)
            this._u32 = new Uint32Array(lohi_from_one(low));
            return;
        }

        if (check_not_in_range(low)) { // Valida a parte low
            throw TypeError(`low not a 32-bit integer: ${low}`);
        }

        if (check_not_in_range(high)) { // Valida a parte high
            throw TypeError(`high not a 32-bit integer: ${high}`);
        }

        this._u32 = new Uint32Array([low, high]); // Armazena as partes low e high.
    }

    get lo() { // Retorna a parte low (32 bits sem sinal)
        return this._u32[0];
    }

    get hi() { // Retorna a parte high (32 bits sem sinal)
        return this._u32[1];
    }

    // Retorna a parte low como inteiro assinado.
    get bot() {
        return this._u32[0] | 0;
    }

    // Retorna a parte high como inteiro assinado.
    get top() {
        return this._u32[1] | 0;
    }

    // Nega o valor de 64 bits.
    neg() {
        const u32 = this._u32;
        const low = (~u32[0] >>> 0) + 1; // Nega low e adiciona 1 (complemento de dois).
        return new this.constructor(
            low >>> 0, // Garante que low seja 32 bits sem sinal.
            ((~u32[1] >>> 0) + (low > 0xffffffff)) >>> 0, // Nega high e adiciona carry se houver.
        );
    }

    // Compara se é igual a outro valor (número ou Int).
    eq(b) {
        const values = lohi_from_one(b); // Converte 'b' para [low, high].
        const u32 = this._u32;
        return (
            u32[0] === values[0] // Compara as partes low
            && u32[1] === values[1] // Compara as partes high
        );
    }

    // Compara se é diferente de outro valor.
    ne(b) {
        return !this.eq(b);
    }

    // Adiciona outro valor (número ou Int).
    add(b) {
        const values = lohi_from_one(b);
        const u32 = this._u32;
        const low = u32[0] + values[0]; // Soma as partes low.
        return new this.constructor(
            low >>> 0, // Garante 32 bits sem sinal.
            (u32[1] + values[1] + (low > 0xffffffff)) >>> 0, // Soma high e adiciona carry.
        );
    }

    // Subtrai outro valor (número ou Int).
    sub(b) {
        const values = lohi_from_one(b);
        const u32 = this._u32;
        // Subtração implementada como soma com complemento de dois do subtraendo.
        const low = u32[0] + (~values[0] >>> 0) + 1;
        return new this.constructor(
            low >>> 0,
            (u32[1] + (~values[1] >>> 0) + (low > 0xffffffff)) >>> 0,
        );
    }

    // Converte o valor de 64 bits para uma string.
    // 'is_pretty' formata a string com underscores para melhor legibilidade.
    toString(is_pretty = false) {
        if (!is_pretty) {
            const low = this.lo.toString(16).padStart(8, '0');
            const high = this.hi.toString(16).padStart(8, '0');
            return '0x' + high + low;
        }
        let high = this.hi.toString(16).padStart(8, '0');
        high = high.substring(0, 4) + '_' + high.substring(4);

        let low = this.lo.toString(16).padStart(8, '0');
        low = low.substring(0, 4) + '_' + low.substring(4);

        return '0x' + high + '_' + low;
    }
}
