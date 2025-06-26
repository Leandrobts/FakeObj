//rw.mjs

import { Int, lohi_from_one } from './int64.mjs'; // Importa Int e lohi_from_one para manipulação de 64 bits

// Classe BufferView: Estende Uint8Array e adiciona métodos para leitura/escrita de múltiplos bytes.
// Utiliza um DataView interno para operações otimizadas.
// Instâncias de BufferView terão seu m_mode definido para WastefulTypedArray
// ao usar o getter .buffer, o que é importante para evitar problemas de GC.
export class BufferView extends Uint8Array {
    constructor(...args) {
        super(...args);
        // Cria um DataView associado ao buffer desta TypedArray para acesso otimizado.
        this._dview = new DataView(this.buffer, this.byteOffset);
    }

    read16(offset) {
        // Lê um valor de 16 bits no offset, usando little-endian (true).
        return this._dview.getUint16(offset, true);
    }

    read32(offset) {
        // Lê um valor de 32 bits no offset, usando little-endian (true).
        return this._dview.getUint32(offset, true);
    }

    read64(offset) {
        // Lê um valor de 64 bits no offset, combinando duas leituras de 32 bits.
        return new Int(
            this._dview.getUint32(offset, true),
            this._dview.getUint32(offset + 4, true),
        );
    }

    write16(offset, value) {
        // Escreve um valor de 16 bits no offset, usando little-endian (true).
        this._dview.setUint16(offset, value, true);
    }

    write32(offset, value) {
        // Escreve um valor de 32 bits no offset, usando little-endian (true).
        this._dview.setUint32(offset, value, true);
    }

    write64(offset, value) {
        // Escreve um valor de 64 bits no offset, dividindo em duas escritas de 32 bits.
        const values = lohi_from_one(value); // Converte o valor para [low, high]
        this._dview.setUint32(offset, values[0], true);
        this._dview.setUint32(offset + 4, values[1], true);
    }
}

// WARNING: As funções read/write de baixo nível (read16, read32, read64, write16, write32, write64)
// que antes existiam neste arquivo foram DEPRECADAS no PSFree. Use BufferView em seu lugar.
// Elas foram removidas para evitar confusão e incentivar o uso da abstração mais eficiente.
