// config.mjs (ATUALIZADO COM ESTRATÉGIA DE TESTE DE OFFSETS)

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

// ... (comentários do PSFree mantidos) ...

function check_bcd(value) {
    for (let i = 0; i <= 12; i += 4) {
        const nibble = (value >>> i) & 0xf;
        if (nibble > 9) return false;
    }
    return true;
}

export function set_target(value) {
    if (!Number.isInteger(value)) {
        throw TypeError(`value not an integer: ${value}`);
    }
    if (value >= 0x20000 || value < 0) {
        throw RangeError(`value >= 0x20000 or value < 0: ${value}`);
    }
    const version = value & 0xffff;
    if (!check_bcd(version)) {
        throw RangeError(`value & 0xffff not in BCD format ${version}`);
    }
    target = value;
}

export let target = null;
// DEFININDO O ALVO PARA 12.02
set_target(0x1202);

// --- Offsets JSC Consolidados para FW 12.02 ---
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8,
        STRUCTURE_ID_FLATTENED_OFFSET: 0x0,
        CELL_TYPEINFO_TYPE_FLATTENED_OFFSET: 0x4,
        CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET: 0x5,
        CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET: 0x6,
        CELL_STATE_FLATTENED_OFFSET: 0x7,
    },
    CallFrame: {
        CALLEE_OFFSET: 0x8,
        ARG_COUNT_OFFSET: 0x10,
        THIS_VALUE_OFFSET: 0x18,
        ARGUMENTS_POINTER_OFFSET: 0x28
    },
    Structure: {
        CELL_SPECIFIC_FLAGS_OFFSET: 0x8,
        TYPE_INFO_TYPE_OFFSET: 0x9,
        TYPE_INFO_MORE_FLAGS_OFFSET: 0xA,
        TYPE_INFO_INLINE_FLAGS_OFFSET: 0xC,
        AGGREGATED_FLAGS_OFFSET: 0x10,
        VIRTUAL_PUT_OFFSET: 0x18,
        PROPERTY_TABLE_OFFSET: 0x20,
        GLOBAL_OBJECT_OFFSET: 0x28,
        PROTOTYPE_OFFSET: 0x30,
        CACHED_OWN_KEYS_OFFSET: 0x48,
        CLASS_INFO_OFFSET: 0x50,
    },
    JSObject: {
        // ### ESTRATÉGIA DE TESTE DE OFFSETS ###
        // A falha atual está na estabilização de 'getAddress'. Isso geralmente é causado
        // por offsets incorretos que definem a estrutura de um objeto JS.
        // Tente uma combinação de cada vez: descomente uma das tentativas abaixo,
        // comente as outras, salve e use o botão "Test Core Primitives (Debug)".

        // --- TENTATIVA 1 (Padrão Moderno - ATUALMENTE ATIVA) ---
        BUTTERFLY_OFFSET: 0x10,
        INLINE_PROPERTIES_OFFSET: 0x10,

        /*
        // --- TENTATIVA 2 (Padrão Antigo - Comum em FWs mais velhas como 9.00) ---
        BUTTERFLY_OFFSET: 0x8,
        INLINE_PROPERTIES_OFFSET: 0x10, // Butterfly pode ser 0x8, mas as props começarem em 0x10
        */

        /*
        // --- TENTATIVA 3 (Outra Variação Antiga) ---
        BUTTERFLY_OFFSET: 0x8,
        INLINE_PROPERTIES_OFFSET: 0x8,
        */
        
        // sizeof JSC::JSObject
        JS_OBJECT_SIZE: 0x10,
        
        // Para WebCore::JSHTMLTextAreaElement
        JSTA_IMPL_OFFSET: 0x18, // VERIFICAR PARA FW 12.02
        JSTA_SIZE: 0x20, // VERIFICAR PARA FW 12.02
    },
    JSFunction: {
        EXECUTABLE_OFFSET: 0x18,
        SCOPE_OFFSET: 0x20,
    },
    JSCallee: {
        GLOBAL_OBJECT_OFFSET: 0x10,
    },
    ClassInfo: {
        M_CACHED_TYPE_INFO_OFFSET: 0x8,
    },
    ArrayBuffer: {
        CONTENTS_IMPL_POINTER_OFFSET: 0x10,
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18,
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20,
        SHARING_MODE_OFFSET: 0x28,
        IS_RESIZABLE_FLAGS_OFFSET: 0x30,
        ARRAYBUFFER_REAL_PTR_POSSIBLE_M_VECTOR: 0x28,
        ARRAYBUFFER_FIELD_0X30: 0x30,
        ARRAYBUFFER_FIELD_0X34: 0x34,
        ARRAYBUFFER_FIELD_0X38: 0x38,
        ARRAYBUFFER_FIELD_0X40: 0x40,
        KnownStructureIDs: {
            JSString_STRUCTURE_ID: null,
            ArrayBuffer_STRUCTURE_ID: 2,
            JSArray_STRUCTURE_ID: null,
            JSObject_Simple_STRUCTURE_ID: null
        }
    },
    ArrayBufferView: {
        STRUCTURE_ID_OFFSET: 0x00,
        FLAGS_OFFSET: 0x04,
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08,
        M_VECTOR_OFFSET: 0x10,
        M_LENGTH_OFFSET: 0x18,
        M_MODE_OFFSET: 0x1C,
        VIEW_SIZE: 0x20
    },
    ArrayBufferContents: {
        SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8,
        DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10,
        SHARED_ARRAY_BUFFER_CONTENTS_IMPL_PTR_OFFSET: 0x20,
        IS_SHARED_FLAG_OFFSET: 0x40,
        RAW_DATA_POINTER_FIELD_CANDIDATE_OFFSET: 0x5C,
        PINNING_FLAG_OFFSET: 0x5D,
    },
    VM: {
        TOP_CALL_FRAME_OFFSET: 0x9E98, // VERIFICAR PARA FW 12.02
    },
    DataView: {
        STRUCTURE_VTABLE_OFFSET: "0x3AD62A0", // VERIFICAR PARA FW 12.02
        DESTROYED_OBJECT_VTABLE: "0x3AD6340", // VERIFICAR PARA FW 12.02
        VTABLE_OFFSET_0x48_METHOD: 0x48,
        VTABLE_OFFSET_0x50_METHOD: 0x50,
        M_MODE_CANDIDATES: [
            0x0000000B,
            0x00000001,
            0x0000000E,
            0x0000000F
       ]
    },
    EXPECTED_BUTTERFLY_ELEMENT_SIZE: 8,

    WEBKIT_IMPORTS: { // VERIFICAR PARA FW 12.02
        offset_wk_stack_chk_fail: "0x178",
        offset_wk_memcpy: "0x188"
    }
};

export const WEBKIT_LIBRARY_INFO = {
    NAME: "libSceNKWebKit.sprx",
    // TODOS OS OFFSETS ABAIXO PRECISAM SER ATUALIZADOS PARA FW 12.02
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
        "JSC::JSObject::put": "0xBD68B0",
        "JSC::Structure::Structure_constructor": "0x1638A50",
        "WTF::fastMalloc": "0x1271810",
        "WTF::fastFree": "0x230C7D0",
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
    ALLOCATION_SIZE: 0x20000,
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
