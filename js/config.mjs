// js/config.mjs

// Firmware: PS4 12.02 (Com base na análise dos TXT fornecidos)
// !! OFFSETS VALIDADOS E ATUALIZADOS COM BASE NOS ARQUIVOS DE DISASSEMBLY FORNECIDOS !!
//    É crucial continuar validando no contexto do seu exploit específico.
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8,    // VALIDADO
        STRUCTURE_ID_FLATTENED_OFFSET: 0x0, 
        CELL_TYPEINFO_TYPE_FLATTENED_OFFSET: 0x4, 
        CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET: 0x5, 
        CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET: 0x6, 
        CELL_STATE_FLATTENED_OFFSET: 0x7,
        // Seus valores originais para STRUCTURE_ID_OFFSET e FLAGS_OFFSET foram removidos
        // para evitar confusão com os *_FLATTENED_OFFSET, que parecem mais detalhados
        // da sua análise do construtor de Structure.
    },
    CallFrame: { // Offsets baseados na análise de CallFrame.txt
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
        // VIRTUAL_PUT_OFFSET foi movido para aqui, pois é um offset DENTRO da Structure.
        // No seu dump, "call qword ptr [rdx+18h]" onde rdx é Structure* sugere isso.
        VIRTUAL_PUT_OFFSET: 0x18, // CANDIDATO FORTE PARA PONTEIRO DE FUNÇÃO VIRTUAL (ex: JSObject::put)
        PROPERTY_STORAGE_CAPACITY_OFFSET: 0x18, // Nota: Mesmo offset que VIRTUAL_PUT_OFFSET, isso é incomum. VERIFIQUE. Se for diferente, ajuste.
                                                // Se o VIRTUAL_PUT_OFFSET for de uma vtable, ele estará no início da Structure (0x0) ou em ClassInfo.
                                                // A sua nota "call qword ptr [rdx+18h]" é a pista.
        PROPERTY_TABLE_OFFSET: 0x20,
        GLOBAL_OBJECT_OFFSET: 0x28,
        PROTOTYPE_OFFSET: 0x30,
        CACHED_OWN_KEYS_OFFSET: 0x48,
        CLASS_INFO_OFFSET: 0x50,
    },
    JSObject: {
        BUTTERFLY_OFFSET: 0x10,
    },
    JSFunction: {
        EXECUTABLE_OFFSET: 0x18, // VALIDADO
        SCOPE_OFFSET: 0x20,
    },
    JSCallee: { 
        GLOBAL_OBJECT_OFFSET: 0x10, // VALIDADO
    },
    ArrayBuffer: {
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // VALIDADO
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, // VALIDADO
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20, // VALIDADO
        SHARING_MODE_OFFSET: 0x28,
        IS_RESIZABLE_FLAGS_OFFSET: 0x30,
        KnownStructureIDs: {
            JSString_STRUCTURE_ID: null,
            ArrayBuffer_STRUCTURE_ID: 2, // VALIDADO
            JSArray_STRUCTURE_ID: null,
            JSObject_Simple_STRUCTURE_ID: null // VÍRGULA ADICIONADA AQUI
        }
    },
    ArrayBufferView: { // Para TypedArrays como Uint8Array, Uint32Array, DataView
        STRUCTURE_ID_OFFSET: 0x00,      // Relativo ao início do JSCell do ArrayBufferView
        FLAGS_OFFSET: 0x04,             // Relativo ao início do JSCell do ArrayBufferView
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, // Ponteiro para o JSArrayBuffer.
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // Ponteiro para ArrayBufferContents (redundante se já tem ASSOCIATED_ARRAYBUFFER_OFFSET?) ou diferente? Verifique.
                                           // Geralmente, a View aponta para o JSArrayBuffer, e este aponta para Contents.
                                           // Manteremos o seu, mas revise se ASSOCIATED_ARRAYBUFFER_OFFSET leva ao JSArrayBuffer, que por sua vez tem CONTENTS_IMPL_POINTER_OFFSET.
        M_VECTOR_OFFSET: 0x10,          // Se CONTENTS_IMPL_POINTER_OFFSET acima for o correto, M_VECTOR_OFFSET pode ser relativo a ArrayBufferContents, não à View.
                                           // No entanto, os logs anteriores sugerem que 0x58 (início da View) + 0x10 (M_VECTOR_OFFSET) = 0x68 funciona para você.
        M_LENGTH_OFFSET: 0x18,          // Comprimento da view.
        M_MODE_OFFSET: 0x1C
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
    ALLOCATION_SIZE: 1048576, // Para o  v10.36, você aumentou para 1MB. Mantenha o valor desejado.
    BASE_OFFSET_IN_DV: 128,
    INITIAL_BUFFER_SIZE: 32
};

export function updateOOBConfigFromUI(docInstance) {
    // ... (sem alterações)
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
