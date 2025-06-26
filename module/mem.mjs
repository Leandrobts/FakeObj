//module/mem.mjs

import { Int, lohi_from_one } from './int64.mjs'; // Importa Int e lohi_from_one para manipulação de 64 bits
import { view_m_vector, view_m_length } from './offset.mjs'; // Importa offsets de TypedArrayView

export let mem = null; // Variável global para a instância de Memory

// Cache de constantes
const off_vector = view_m_vector / 4; // Offset do m_vector em termos de Uint32Array
const off_vector2 = (view_m_vector + 4) / 4; // Offset da segunda parte (high) do m_vector
const isInteger = Number.isInteger; // Atalho para Number.isInteger

function init_module(memory) {
    mem = memory; // Inicializa a variável global 'mem' com a instância de Memory
}

function add_and_set_addr(mem, offset, base_lo, base_hi) {
    const values = lohi_from_one(offset); // Converte o offset para [low, high]
    const main = mem._main; // Acessa o Uint32Array principal da primitiva

    const low = base_lo + values[0]; // Adiciona a parte low

    // Não precisa de ">>> 0" aqui para conversão para unsigned
    main[off_vector] = low; // Define a parte low do m_vector
    main[off_vector2] = base_hi + values[1] + (low > 0xffffffff); // Define a parte high do m_vector, com carry
}

export class Addr extends Int { // Addr estende Int para representar endereços de 64 bits
    read8(offset) {
        const m = mem; // Acessa a instância global de Memory
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) { // Se o offset for um número inteiro dentro dos limites de 32 bits
            m._set_addr_direct(this); // Define o endereço diretamente
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi); // Adiciona o offset e define o endereço
            offset = 0; // O offset se torna 0 para a leitura
        }

        return m.read8_at(offset); // Lê 8 bits no offset
    }

    read16(offset) {
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        return m.read16_at(offset);
    }

    read32(offset) {
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        return m.read32_at(offset);
    }

    read64(offset) {
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        return m.read64_at(offset);
    }

    readp(offset) { // Lê um ponteiro (Addr)
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        return m.readp_at(offset);
    }

    write8(offset, value) {
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        m.write8_at(offset, value);
    }

    write16(offset, value) {
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        m.write16_at(offset, value);
    }

    write32(offset, value) {
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        m.write32_at(offset, value);
    }

    write64(offset, value) {
        const m = mem;
        if (isInteger(offset) && 0 <= offset && offset <= 0xffffffff) {
            m._set_addr_direct(this);
        } else {
            add_and_set_addr(m, offset, this.lo, this.hi);
            offset = 0;
        }

        m.write64_at(offset, value);
    }
}

// Classe Memory: Abstrai a leitura e escrita arbitrária na memória do processo.
// Requer:
// * main: Uint32Array cujo m_vector será corrompido para apontar para 'worker'.
// * worker: DataView para realizar as operações de leitura/escrita.
// * obj: Objeto JS com propriedades 'addr' e '0' usado por addrof/fakeobj.
// * addr_addr: Endereço do slot da propriedade 'addr' em 'obj'.
// * fake_addr: Endereço do slot da propriedade '0' em 'obj'.
export class Memory {
    constructor(main, worker, obj, addr_addr, fake_addr) {
        this._main = main; // Uint32Array principal (controlado pelo JS)
        this._worker = worker; // DataView que fará as operações reais de R/W
        this._obj = obj; // Objeto de ponteiro para addrof/fakeobj
        this._addr_low = addr_addr.lo; // Parte low do endereço de 'obj.addr'
        this._addr_high = addr_addr.hi; // Parte high do endereço de 'obj.addr'
        this._fake_low = fake_addr.lo; // Parte low do endereço de 'obj[0]'
        this._fake_high = fake_addr.hi; // Parte high do endereço de 'obj[0]'

        // Expande o comprimento do 'main' para o máximo possível (0xFFFFFFFF)
        // Isso permite que o 'worker' (DataView) acesse arbitrariamente a memória
        main[view_m_length / 4] = 0xffffffff;

        init_module(this); // Inicializa a variável global 'mem' com esta instância

        // As linhas problemáticas que manipulavam `worker` aqui foram removidas do construtor
        // pois pertencem ao método `fakeobj()`. O construtor deve apenas inicializar.
        const buf = new ArrayBuffer(0); // Buffer vazio para criar TypedArrays temporários

        // Configura _cpysrc para operações de cópia de memória
        const src = new Uint8Array(buf); // Uint8Array temporário para origem da cópia
        const sset = new Uint32Array(buf); // Uint32Array para definir o m_vector e length de src
        const sset_p = this.addrof(sset); // Endereço de sset
        sset_p.write64(off_vector, this.addrof(src).add(off_vector)); // Aponta sset para o m_vector de src
        sset_p.write32(view_m_length / 4, 3); // Define o comprimento de sset
        this._cpysrc = src; // Armazena a referência para src
        this._src_setter = sset; // Armazena a referência para sset

        // Configura _cpydst para operações de cópia de memória
        const dst = new Uint8Array(buf); // Uint8Array temporário para destino da cópia
        const dset = new Uint32Array(buf); // Uint32Array para definir o m_vector e length de dst
        const dset_p = this.addrof(dset); // Endereço de dset
        dset_p.write64(off_vector, this.addrof(dst).add(off_vector)); // Aponta dset para o m_vector de dst
        dset_p.write32(view_m_length / 4, 3); // Define o comprimento de dset
        dset[2] = 0xffffffff; // Define um comprimento alto para o dst para permitir escrita arbitrária
        this._cpydst = dst; // Armazena a referência para dst
        this._dst_setter = dset; // Armazena a referência para dset
    }

    // Copia 'len' bytes de 'src' para 'dst'. 'dst' e 'src' podem se sobrepor.
    cpy(dst, src, len) {
        if (!(isInteger(len) && 0 <= len && len <= 0xffffffff)) {
            throw TypeError('len not a unsigned 32-bit integer');
        }

        const dvals = lohi_from_one(dst); // Converte dst para [low, high]
        const svals = lohi_from_one(src); // Converte src para [low, high]
        const dset = this._dst_setter; // Setter do destino
        const sset = this._src_setter; // Setter da origem

        dset[0] = dvals[0]; // Define a parte low do endereço de destino
        dset[1] = dvals[1]; // Define a parte high do endereço de destino
        sset[0] = svals[0]; // Define a parte low do endereço de origem
        sset[1] = svals[1]; // Define a parte high do endereço de origem
        sset[2] = len; // Define o comprimento da cópia

        this._cpydst.set(this._cpysrc); // Realiza a cópia usando set() do Uint8Array
    }

    // Aloca memória gerenciada pelo Garbage Collector.
    // Retorna [address_of_memory, backer]. 'backer' é o JSCell que mantém a memória viva.
    gc_alloc(size) {
        if (!isInteger(size)) {
            throw TypeError('size not a integer');
        }
        if (size < 0) {
            throw RangeError('size is negative');
        }

        const fastLimit = 1000; // Limite para alocação rápida
        size = (size + 7 & ~7) >> 3; // Alinha e converte tamanho para float64 elements
        if (size > fastLimit) {
            throw RangeError('size is too large');
        }

        const backer = new Float64Array(size); // Aloca um Float64Array para backing
        // Retorna o endereço do buffer da Float64Array e a própria Float64Array como backer.
        return [mem.addrof(backer).readp(view_m_vector), backer];
    }

    // Cria um objeto JavaScript "falso" em um dado endereço.
    fakeobj(addr) {
        const values = lohi_from_one(addr); // Converte o endereço para [low, high]
        const worker = this._worker; // DataView usado para as operações
        const main = this._main; // Uint32Array principal

        main[off_vector] = this._fake_low; // Define o m_vector de 'main' para apontar para o slot de 'obj[0]'
        main[off_vector2] = this._fake_high; //
        worker.setUint32(0, values[0], true); // Escreve a parte low do endereço falso em 'obj[0]'
        worker.setUint32(4, values[1], true); // Escreve a parte high do endereço falso em 'obj[0]'
        return this._obj[0]; // Retorna o objeto falso
    }

    // Obtém o endereço de um objeto JavaScript.
    addrof(object) {
        // Blacklist de null e verificação de tipo para garantir que seja um objeto JS válido.
        if (object === null
            || (typeof object !== 'object' && typeof object !== 'function')
        ) {
            throw TypeError('argument not a JS object');
        }

        const obj = this._obj; // Objeto de ponteiro
        const worker = this._worker; // DataView
        const main = this._main; // Uint32Array principal

        obj.addr = object; // Atribui o objeto alvo à propriedade 'addr' do objeto de ponteiro

        main[off_vector] = this._addr_low; // Define o m_vector de 'main' para apontar para o slot de 'obj.addr'
        main[off_vector2] = this._addr_high; //

        // Lê o endereço do objeto alvo a partir do 'worker'
        const res = new Addr(
            worker.getUint32(0, true),
            worker.getUint32(4, true),
        );
        obj.addr = null; // Limpa a referência para evitar vazamentos

        return res;
    }

    // Define o endereço para a primitiva de leitura/escrita direta.
    // Espera 'addr' como uma instância de Int.
    _set_addr_direct(addr) {
        const main = this._main; // Uint32Array principal
        main[off_vector] = addr.lo; // Define o low do endereço
        main[off_vector2] = addr.hi; // Define o high do endereço
    }

    // Define o endereço base para as operações de leitura/escrita.
    set_addr(addr) {
        const values = lohi_from_one(addr); // Converte o endereço para [low, high]
        const main = this._main; // Uint32Array principal
        main[off_vector] = values[0]; // Define o low do endereço
        main[off_vector2] = values[1]; // Define o high do endereço
    }

    // Obtém o endereço atualmente definido na primitiva.
    get_addr() {
        const main = this._main; // Uint32Array principal
        return new Addr(main[off_vector], main[off_vector2]); // Retorna o endereço como Addr
    }

    // Métodos de leitura
    read8(addr) {
        this.set_addr(addr); // Define o endereço
        return this._worker.getUint8(0); // Lê 8 bits no offset 0
    }

    read16(addr) {
        this.set_addr(addr);
        return this._worker.getUint16(0, true);
    }

    read32(addr) {
        this.set_addr(addr);
        return this._worker.getUint32(0, true);
    }

    read64(addr) {
        this.set_addr(addr);
        const worker = this._worker;
        return new Int(worker.getUint32(0, true), worker.getUint32(4, true));
    }

    // Lê um ponteiro (Addr) a partir do endereço dado.
    readp(addr) {
        this.set_addr(addr);
        const worker = this._worker;
        return new Addr(worker.getUint32(0, true), worker.getUint32(4, true));
    }

    // Métodos de leitura com offset a partir do endereço já definido
    read8_at(offset) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        return this._worker.getUint8(offset);
    }

    read16_at(offset) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        return this._worker.getUint16(offset, true);
    }

    read32_at(offset) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        return this._worker.getUint32(offset, true);
    }

    read64_at(offset) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        const worker = this._worker;
        return new Int(
            worker.getUint32(offset, true),
            worker.getUint32(offset + 4, true),
        );
    }

    readp_at(offset) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        const worker = this._worker;
        return new Addr(
            worker.getUint32(offset, true),
            worker.getUint32(offset + 4, true),
        );
    }

    // Métodos de escrita
    write8(addr, value) {
        this.set_addr(addr);
        this._worker.setUint8(0, value);
    }

    write16(addr, value) {
        this.set_addr(addr);
        this._worker.setUint16(0, value, true);
    }

    write32(addr, value) {
        this.set_addr(addr);
        this._worker.setUint32(0, value, true);
    }

    write64(addr, value) {
        const values = lohi_from_one(value);
        this.set_addr(addr);
        const worker = this._worker;
        worker.setUint32(0, values[0], true);
        worker.setUint32(4, values[1], true);
    }

    // Métodos de escrita com offset a partir do endereço já definido
    write8_at(offset, value) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        this._worker.setUint8(offset, value);
    }

    write16_at(offset, value) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        this._worker.setUint16(offset, value, true);
    }

    write32_at(offset, value) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        this._worker.setUint32(offset, value, true);
    }

    write64_at(offset, value) {
        if (!isInteger(offset)) {
            throw TypeError('offset not a integer');
        }
        const values = lohi_from_one(value);
        const worker = this._worker;
        worker.setUint32(offset, values[0], true);
        worker.setUint32(offset + 4, values[1], true);
    }
}
