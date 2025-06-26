// config.mjs (ATUALIZADO PARA FW 12.02 E CONSOLIDADO)

// Formato do firmware alvo usado por PSFree:
// 0xC_MM_mm
// * C console - PS4 (0) ou PS5 (1) (1 bit)
// * MM major version - parte inteira da versão do firmware (8 bits)
// * mm minor version - parte fracionária da versão do firmware (8 bits)
// Exemplos:
// * PS4 10.00 -> C = 0 MM = 10 mm = 0 -> 0x0_10_00
// * PS5 4.51 -> C = 1 MM = 4 mm = 51 -> 0x1_04_51

// Verifica se o valor está no formato BCD (Binary Coded Decimal).
// Assume inteiro e está no intervalo [0, 0xffff].
function check_bcd(value) {
    for (let i = 0; i <= 12; i += 4) {
        const nibble = (value >>> i) & 0xf;

        if (nibble > 9) {
            return false;
        }
    }

    return true;
}

export function set_target(value) {
    if (!Number.isInteger(value)) {
        throw TypeError(`value not an integer: ${value}`);
    }

    if (value >= 0x20000 || value < 0) { // Limite de 0x20000 para a versão do firmware
        throw RangeError(`value >= 0x20000 or value < 0: ${value}`);
    }

    const version = value & 0xffff;
    if (!check_bcd(version)) { // Verifica o formato BCD.
        throw RangeError(`value & 0xffff not in BCD format ${version}`);
    }

    target = value;
}

export let target = null;
// DEFININDO O ALVO PARA 12.02
set_target(0x1202);

// --- Offsets JSC Consolidados para FW 12.02 ---
// Offsets do antigo offsets.mjs foram movidos para cá para eliminar conflitos.
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8,
        STRUCTURE_ID_FLATTENED_OFFSET: 0x0,
        CELL_TYPEINFO_TYPE_FLATTENED_OFFSET: 0x4,
        CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET: 0x5,
        CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET: 0x6,
        CELL_STATE_FLATTENED_OFFSET: 0x7,
    },
    JSObject: {
        // Offset para o ponteiro butterfly (armazenamento de propriedades fora do objeto)
        BUTTERFLY_OFFSET: 0x10, // VERIFICAR PARA FW 12.02

        // Início das propriedades inline (JSValues) - Onde os dados do objeto começam
        INLINE_PROPERTIES_OFFSET: 0x10, // VERIFICAR PARA FW 12.02

        // sizeof JSC::JSObject
        JS_OBJECT_SIZE: 0x10, // VERIFICAR PARA FW 12.02

        // Para WebCore::JSHTMLTextAreaElement
        JSTA_IMPL_OFFSET: 0x18, // ponteiro para o objeto DOM. VERIFICAR PARA FW 12.02
        JSTA_SIZE: 0x20, // sizeof JSHTMLTextAreaElement. VERIFICAR PARA FW 12.02
    },
    ArrayBufferView: {
        // Offsets para JSC::JSArrayBufferView
        STRUCTURE_ID_OFFSET: 0x00,
        FLAGS_OFFSET: 0x04,
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, // Ponteiro para o JSArrayBuffer real
        M_VECTOR_OFFSET: 0x10,          // Ponteiro interno para os dados da view
        M_LENGTH_OFFSET: 0x18,          // Comprimento da view (em elementos)
        M_MODE_OFFSET: 0x1C,            // Flags de modo da view
        VIEW_SIZE: 0x20,                 // sizeof JSArrayBufferView
    },
    Structure: {
        CLASS_INFO_OFFSET: 0x50,
        // ... outros offsets de Structure ...
    },
    ClassInfo: {
        M_CACHED_TYPE_INFO_OFFSET: 0x8,
    },
    ArrayBuffer: {
        CONTENTS_IMPL_POINTER_OFFSET: 0x10,
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18,
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20,
        // ... outros offsets de ArrayBuffer
    },
    DataView: {
        STRUCTURE_VTABLE_OFFSET: "0x3AD62A0", // VERIFICAR PARA FW 12.02
        M_MODE_CANDIDATES: [
            0x0000000B,
            0x00000001,
            0x0000000E,
            0x0000000F
       ]
    },
    EXPECTED_BUTTERFLY_ELEMENT_SIZE: 8,
    WEBKIT_IMPORTS: {
        offset_wk_stack_chk_fail: "0x178", // VERIFICAR PARA FW 12.02
        offset_wk_memcpy: "0x188"         // VERIFICAR PARA FW 12.02
    }
};


export const WEBKIT_LIBRARY_INFO = {
    NAME: "libSceNKWebKit.sprx",
    // TODOS OS OFFSETS DE FUNÇÃO E DADOS ABAIXO SÃO DO FW 9.00 E PRECISAM SER ATUALIZADOS PARA 12.02
    FUNCTION_OFFSETS: {
        "JSC::JSFunction::create": "0x58A1D0",
        "JSC::InternalFunction::createSubclassStructure": "0xA86580",
        "WTF::StringImpl::destroy": "0x10AA800",
        "mprotect_plt_stub": "0x1A08",
        // ... outros ...
    },
    DATA_OFFSETS: {
        "JSC::JSArrayBufferView::s_info": "0x3AE5040",
        // ... outros ...
    }
};

export let OOB_CONFIG = {
    ALLOCATION_SIZE: 0x20000, // Reduzido para 64KB para maior estabilidade 0x8000 32KB
    BASE_OFFSET_IN_DV: 128,
    INITIAL_BUFFER_SIZE: 32
};


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
