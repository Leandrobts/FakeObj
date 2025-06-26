// config.mjs

/* Copyright (C) 2023-2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.  */

// webkitgtk 2.34.4 foi usado para desenvolver as partes portáteis do exploit
// antes de migrar para ps4 8.03.
// webkitgtk 2.34.4 foi construído com a variável cmake ENABLE_JIT=OFF,
// que pode afetar o tamanho de SerializedScriptValue.
// Este alvo não é mais suportado.

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
set_target(0x900); // Define o alvo inicial como PS4 9.00.

// --- Seus offsets JSC existentes ---
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8,    // VALIDADO
        STRUCTURE_ID_FLATTENED_OFFSET: 0x0,
        CELL_TYPEINFO_TYPE_FLATTENED_OFFSET: 0x4,
        CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET: 0x5,
        CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET: 0x6,
        CELL_STATE_FLATTENED_OFFSET: 0x7,
    },
    CallFrame: {
        CALLEE_OFFSET: 0x8,         // De JSC::ProtoCallFrame::callee()
        ARG_COUNT_OFFSET: 0x10,     // De JSC::ProtoCallFrame::argumentCountIncludingThis()
        THIS_VALUE_OFFSET: 0x18,    // De JSC::ProtoCallFrame::thisValue()
        ARGUMENTS_POINTER_OFFSET: 0x28 // De JSC::ProtoCallFrame::argument(ulong)
    },
    Structure: { // Offsets DENTRO da estrutura Structure
        CELL_SPECIFIC_FLAGS_OFFSET: 0x8,
        TYPE_INFO_TYPE_OFFSET: 0x9,
        TYPE_INFO_MORE_FLAGS_OFFSET: 0xA,
        TYPE_INFO_INLINE_FLAGS_OFFSET: 0xC,
        AGGREGATED_FLAGS_OFFSET: 0x10,
        VIRTUAL_PUT_OFFSET: 0x18, // CANDIDATO FORTE PARA PONTEIRO DE FUNÇÃO VIRTUAL
        PROPERTY_TABLE_OFFSET: 0x20,
        GLOBAL_OBJECT_OFFSET: 0x28,
        PROTOTYPE_OFFSET: 0x30,
        CACHED_OWN_KEYS_OFFSET: 0x48,
        CLASS_INFO_OFFSET: 0x50,
    },
    // CORREÇÃO AQUI: MESCLANDO PROPRIEDADES DE JSOBJECT
    JSObject: {
        BUTTERFLY_OFFSET: 0x10,
        js_inline_prop: 0x10, // Start of the array of inline properties (JSValues)
        size_jsobj: 0x10, // sizeof JSC::JSObject
        jsta_impl: 0x18, // offset to m_wrapped, pointer to a DOM object for HTMLTextAreaElement
        size_jsta: 0x20 // sizeof WebCore::JSHTMLTextAreaElement
    },
    JSFunction: {
        EXECUTABLE_OFFSET: 0x18, // VALIDADO
        SCOPE_OFFSET: 0x20,
    },
    JSCallee: {
        GLOBAL_OBJECT_OFFSET: 0x10, // VALIDADO
    },
    ClassInfo: { // NOVO: Adicionado para a estratégia de vazamento de ClassInfo
        M_CACHED_TYPE_INFO_OFFSET: 0x8, // Offset comum para m_cachedTypeInfo dentro de ClassInfo.
    },
    ArrayBuffer: {
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // VALIDADO - Ponteiro para os dados brutos do buffer
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, // VALIDADO - Tamanho do buffer
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20, // VALIDADO - Cópia do ponteiro de dados (redundante?)
        SHARING_MODE_OFFSET: 0x28, // Offset do sharing mode (ArrayBuffer)
        IS_RESIZABLE_FLAGS_OFFSET: 0x30, // Offset de flags de redimensionamento (ArrayBuffer)
        ARRAYBUFFER_REAL_PTR_POSSIBLE_M_VECTOR: 0x28, // a1[5] - base de dados no loop de limpeza/validação
        ARRAYBUFFER_FIELD_0X30: 0x30, // *((_DWORD *)a1 + 12) - usado em sub_1C01140
        ARRAYBUFFER_FIELD_0X34: 0x34, // *((_DWORD *)a1 + 13) - usado como contador/tamanho no loop
        ARRAYBUFFER_FIELD_0X38: 0x38, // a1[7] - liberado por fastFree
        ARRAYBUFFER_FIELD_0X40: 0x40, // a1[8] - testado e liberado por BitVector::OutOfLineBits::destroy
        KnownStructureIDs: {
            JSString_STRUCTURE_ID: null,
            ArrayBuffer_STRUCTURE_ID: 2, // VALIDADO
            JSArray_STRUCTURE_ID: null,
            JSObject_Simple_STRUCTURE_ID: null
        }
    },
    ArrayBufferView: { // Para TypedArrays como Uint8Array, Uint32Array, DataView
        // Estes são offsets DENTRO da estrutura ArrayBufferView
        STRUCTURE_ID_OFFSET: 0x00,      // Relativo ao início do JSCell do ArrayBufferView
        FLAGS_OFFSET: 0x04,             // Relativo ao início do JSCell do ArrayBufferView
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, // Ponteiro para o JSArrayBuffer real que esta view usa.
        
        // NOTA IMPORTANTE: M_VECTOR_OFFSET, M_LENGTH_OFFSET e M_MODE_OFFSET para DataView
        // Podem ser diferentes de ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET e SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START.
        // Se a corrupção estiver no backing ArrayBuffer, então se refere aos offsets do ArrayBuffer.
        // Se o DataView tem suas próprias cópias, esses offsets abaixo são usados.
        // A hipótese é que DataView acessa esses a partir de sua própria estrutura.
        M_VECTOR_OFFSET: 0x10,          // Ponteiro interno de dados da view (comum para TypedArrays)
        M_LENGTH_OFFSET: 0x18,          // Comprimento da view (Number of elements * element_size)
        M_MODE_OFFSET: 0x1C             // Offset para m_mode/TypeFlags dentro de ArrayBufferView
    },
    ArrayBufferContents: {
        SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8,   // VALIDADO
        DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10, // VALIDADO
        SHARED_ARRAY_BUFFER_CONTENTS_IMPL_PTR_OFFSET: 0x20,
        IS_SHARED_FLAG_OFFSET: 0x40,
        RAW_DATA_POINTER_FIELD_CANDIDATE_OFFSET: 0x5C,
        PINNING_FLAG_OFFSET: 0x5D,
    },
    VM: {
        TOP_CALL_FRAME_OFFSET: 0x9E98, // VALIDADO
    },
    // NOVO: Adicione o offset do vtable da JSC::Structure para DataView aqui
    DataView: {
        STRUCTURE_VTABLE_OFFSET: 0x3AD62A0, // Já confirmado como o vtable do DataView
        DESTROYED_OBJECT_VTABLE: 0x3AD6340, // A vtable para a qual o objeto aponta após limpeza/destruição
        VTABLE_OFFSET_0x48_METHOD: 0x48, // Método chamado por a1->vtable + 72LL
        VTABLE_OFFSET_0x50_METHOD: 0x50, // Método chamado por a1->vtable + 80LL

        // NOVO: Valor a testar para M_MODE_VALUE
        // O valor 0x0000000B é um candidato inicial.
        // Valores comuns em outras versões: 0x00000001, 0x00000003, 0x00000004, 0x0000000E, 0x0000000F
        M_MODE_VALUE: 0x0000000B, // Valor padrão que será o primeiro a ser testado
        M_MODE_CANDIDATES: [ // Lista de candidatos para tentativa e erro
            0x0000000B, // Já testado e provável (Bitfield: IsJSCapableBuffer | IsTypedView | IsDetached)
            0x00000001, // Outro candidato comum (IsJSCapableBuffer)
            0x0000000E, // Outro candidato comum (IsJSCapableBuffer | IsTypedView | IsDetached | CanBeShared)
            0x0000000F, // Outro candidato (com IsResizable)
       ]
    },
    // Adicionado do PSFree:
    EXPECTED_BUTTERFLY_ELEMENT_SIZE: 8, // Constante para JSValue (8 bytes)

    WEBKIT_IMPORTS: { // Offsets de funções importadas pelo WebKit (para FW 9.00)
        offset_wk_stack_chk_fail: 0x178, // offset to __stack_chk_fail
        offset_wk_memcpy: 0x188 // offset to memcpy
    }
};

export const WEBKIT_LIBRARY_INFO = {
    NAME: "libSceNKWebKit.sprx",
    FUNCTION_OFFSETS: {
        "JSC::JSFunction::create": "0x58A1D0",
        "JSC::InternalFunction::createSubclassStructure": "0xA86580",
        "WTF::StringImpl::destroy": "0x10AA800",
        "bmalloc::Scavenger::schedule": "0x2EBDB0",
        "WebCore::JSLocation::createPrototype": "0xD2E30",
        "WebCore::cacheDOMStructure": "0x740F30",
        "mprotect_plt_stub": "0x1A08",
        "JSC::JSWithScope::create": "0x9D6990",
        "JSC::JSObject::putByIndex": "0x1EB3B00",
        "JSC::JSInternalPromise::create": "0x112BB00",
        "JSC::JSInternalPromise::then": "0x1BC2D70",
        "JSC::loadAndEvaluateModule": "0xFC2900",
        "JSC::ArrayBuffer::create_from_arraybuffer_ref": "0x170A490",
        "JSC::ArrayBuffer::create_from_contents": "0x10E5320",
        "JSC::SymbolObject::finishCreation": "0x102C8F0",
        "JSC::StructureCache::emptyStructureForPrototypeFromBaseStructure": "0xCCF870",
        "JSC::JSObject::put": "0xBD68B0", // Este é um bom candidato para VIRTUAL_PUT_OFFSET
        "JSC::Structure::Structure_constructor": "0x1638A50",
        "WTF::fastMalloc": "0x1271810", // Verifique se este é o principal ou o de 0x230C490
        "WTF::fastFree": "0x230C7D0", // Já confirmado e utilizado
        "JSValueIsSymbol": "0x126D940",
        "JSC::JSArray::getOwnPropertySlot": "0x2322630",
        "JSC::JSGlobalObject::visitChildren_JSCell": "0x1A5F740",
        "JSC::JSCallee::JSCallee_constructor": "0x2038D50",
        "gadget_lea_rax_rdi_plus_20_ret": "0x58B860",
        "JSC::throwConstructorCannotBeCalledAsFunctionTypeError": "0x112BBC0",
    },
    DATA_OFFSETS: {
        "JSC::JSArrayBufferView::s_info": "0x3AE5040",
        "JSC::DebuggerScope::s_info": "0x3AD5670",
        "JSC::Symbols::Uint32ArrayPrivateName": "0x3CC7968",
        "JSC::Symbols::Float32ArrayPrivateName": "0x3CC7990",
        "JSC::Symbols::Float64ArrayPrivateName": "0x3CC79B8",
        "JSC::Symbols::execPrivateName": "0x3CC7A30",
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
