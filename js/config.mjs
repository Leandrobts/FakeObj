// js/config.mjs

// Firmware: PS4 12.02 (Com base na análise dos TXT fornecidos)
// !! OFFSETS VALIDADOS E ATUALIZADOS COM BASE NOS ARQUIVOS DE DISASSEMBLY FORNECIDOS !!
//    É crucial continuar validando no contexto do seu exploit específico.
export const JSC_OFFSETS = {
    JSCell: {
        // VALIDADO: `mov rdx, [rsi+8]` em `JSC::JSObject::put` (funcoes.txt)
        // rsi é JSCell*, rdx é Structure*.
        STRUCTURE_POINTER_OFFSET: 0x8,

        // Outros campos comuns do JSCell (podem variar, precisam de validação se usados)
        // CELL_FLAGS_OFFSET: 0x0, // Exemplo, pode conter o tipo e flags de GC
        // STRUCTURE_ID_OFFSET: 0x4, // Se o ID numérico estivesse inline após flags (menos comum que ponteiro)
    },
    Structure: { // Offsets DENTRO da estrutura Structure (apontada por JSCell.STRUCTURE_POINTER_OFFSET)
        // Estes são mais difíceis de obter sem depuração ou análise mais profunda da struct Structure.
        // Exemplos do que procurar:
        // TYPE_INFO_OFFSET: 0x10, // Offset para TypeInfo dentro da Structure
        // CLASS_INFO_OFFSET: 0x18, // Offset para ClassInfo (contém nome da classe, etc.)
        // PROTOTYPE_OFFSET: 0x20, // Offset para o objeto protótipo
        // GLOBAL_OBJECT_OFFSET: 0x0, // Se a Structure tiver um ponteiro para o GlobalObject
    },
    JSObject: {
        // Ponteiro para o Butterfly (armazenamento de propriedades nomeadas)
        // Comum ser após o cabeçalho JSCell (Structure* em 0x8).
        // Os arquivos TXT não confirmaram este diretamente para JSObject genérico.
        BUTTERFLY_OFFSET: 0x10, // CANDIDATO: Ponteiro para o Butterfly
    },
    ArrayBuffer: {
        // VALIDADO (de JSC::ArrayBuffer::create em JSC ArrayBuffer.txt):
        // `mov [rax+8], rbx` onde rax é JSArrayBuffer* e rbx é ArrayBufferContents*
        CONTENTS_IMPL_POINTER_OFFSET: 0x8, // Ponteiro para a estrutura ArrayBufferContents

        // MANTIDO (de JSC::ArrayBuffer::create em JSC ArrayBuffer.txt):
        // `mov [rax+18h], rdx`. rdx pode ser o tamanho. Necessita mais contexto para rdx.
        // Este é o tamanho do ArrayBuffer como visto pelo JS, não necessariamente o m_sizeInBytes do Contents.
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, // CANDIDATO: Tamanho do ArrayBuffer
    },
    ArrayBufferView: { // Para TypedArrays como Uint8Array, Uint32Array, DataView
        // VALIDADO (de JSObjectGetTypedArrayBytesPtr.txt):
        // `mov rax, [rdi+10h]` onde rdi é a View, rax é ArrayBufferContents*
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // Ponteiro para ArrayBufferContents

        // Outros campos comuns em Views (precisam de validação):
        // LENGTH_OFFSET: 0x18, // Número de elementos na view
        // BYTE_OFFSET_IN_BUFFER: 0x20, // Offset em bytes dentro do ArrayBuffer
        // MODE_OFFSET: 0x24, // Ex: WastefulSweeping, NonWastefulSweeping
    },
    ArrayBufferContents: { // Estrutura apontada por ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET
                           // e ArrayBufferView.CONTENTS_IMPL_POINTER_OFFSET

        // VALIDADO (de JSObjectGetTypedArrayBytesPtr.txt):
        // `mov rcx, [rax+8]` onde rax é ArrayBufferContents*, rcx é m_size
        SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8, // m_sizeInBytes (tamanho real do buffer de dados)

        // VALIDADO (de JSObjectGetTypedArrayBytesPtr.txt):
        // `mov rdx, [rax+10h]` onde rax é ArrayBufferContents*, rdx é m_dataPointer
        DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10, // m_dataPointer (ponteiro para os bytes brutos)

        // Outros campos possíveis (precisam de validação):
        // REF_COUNT_OFFSET: 0x0, // Contagem de referências
        // DESTRUCTOR_OFFSET: 0x4 ou um ponteiro em 0x0 se for o primeiro campo após vtable
    },
    JSFunction: {
        // Estes são mais complexos e dependem da estrutura JSFunction específica
        // EXECUTABLE_OFFSET: 0x18, // Ponteiro para FunctionExecutable
        // SCOPE_OFFSET: 0x20,      // Ponteiro para JSScope
    },
    // ... (outras estruturas como SymbolObject, etc., podem ser adicionadas conforme necessário)

    // IDs de Estrutura Numéricos. VOCÊ PRECISA PREENCHER ESTES VALORES DA SUA ANÁLISE DOS BINÁRIOS.
    // Estes são essenciais para a técnica de "objeto falso".
    // Os valores abaixo são APENAS EXEMPLOS e provavelmente estão INCORRETOS para seu alvo.
    KnownStructureIDs: {
        // Exemplo: JSString_STRUCTURE_ID: 0x01040C00, // Encontre o valor real!
        // Exemplo: ArrayBuffer_STRUCTURE_ID: 0x01082300, // Encontre o valor real!
        // Exemplo: JSArray_STRUCTURE_ID: 0x01080300, // Encontre o valor real!
        // Exemplo: JSObject_Simple_STRUCTURE_ID: 0x010400F0, // Para {} // Encontre o valor real!
        // Adicione mais conforme necessário
        JSString_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
        ArrayBuffer_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
        JSArray_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
        JSObject_Simple_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
    }
};

// Informações da biblioteca WebKit (para calcular endereços base a partir de leaks)
// Estes são nomes simbólicos. Os valores reais dos offsets devem ser preenchidos
// a partir de um WebKit desmontado da MESMA VERSÃO do PS4 12.02.
export const WEBKIT_LIBRARY_INFO = {
    // Nome da biblioteca como aparece no sistema ou depurador
    LIBRARY_NAME: "libSceNKWebkit.sprx", // ou similar

    // Offsets de funções conhecidas DENTRO da biblioteca WebKit.
    // Estes são exemplos. Você precisará encontrar funções e seus offsets.
    FUNCTION_OFFSETS: {
        // Exemplo: "WTF::fastMalloc": 0x123450, // Substitua pelo offset real
        // Exemplo: "JSC::JSObject::put": 0xBD6A9C, // (O endereço em funcoes.txt - BD6A9C)
                                                // Se este for o endereço absoluto já, não é um offset.
                                                // Se for um offset de libSceNKWebkit.sprx, use aqui.
        // O ideal é ter offsets de funções não exportadas, mas estáveis.
    },

    // Offsets de entradas na Global Offset Table (GOT) que apontam para funções
    // em outras bibliotecas (ex: libc, libkernel). Ler estes pode vazar endereços de outras libs.
    GOT_ENTRIES: {
        // Exemplo: "got_memcpy": 0x2F00120, // Offset da entrada da GOT para memcpy
        // Exemplo: "got_pthread_create": 0x2F00128,
    }
};

// Configuração para a primitiva Out-Of-Bounds
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768, // Tamanho do ArrayBuffer usado para a primitiva OOB
    BASE_OFFSET_IN_DV: 128,  // Offset onde a DataView "controlada" começa dentro do ArrayBuffer
    INITIAL_BUFFER_SIZE: 32 // Tamanho inicial do buffer para a trigger (pode não ser mais usado)
};

// Função para atualizar OOB_CONFIG da UI (se houver) - Mantenha como estava
export function updateOOBConfigFromUI(docInstance) {
    if (!docInstance) return;
    const oobAllocSizeEl = docInstance.getElementById('oobAllocSize');
    const baseOffsetEl = docInstance.getElementById('baseOffset');
    const initialBufSizeEl = docInstance.getElementById('initialBufSize');

    if (oobAllocSizeEl && oobAllocSizeEl.value !== undefined) {
        const val = parseInt(oobAllocSizeEl.value, 10);
        if (!isNaN(val) && val > 0) OOB_CONFIG.ALLOCATION_SIZE = val;
    }
    if (baseOffsetEl && baseOffsetEl.value !== undefined) {
        const val = parseInt(baseOffsetEl.value, 10);
        if (!isNaN(val) && val >= 0) OOB_CONFIG.BASE_OFFSET_IN_DV = val;
    }
    if (initialBufSizeEl && initialBufSizeEl.value !== undefined) {
        const val = parseInt(initialBufSizeEl.value, 10);
        if (!isNaN(val) && val > 0) OOB_CONFIG.INITIAL_BUFFER_SIZE = val;
    }
}
