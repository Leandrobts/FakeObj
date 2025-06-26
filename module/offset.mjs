//module/offset.mjs

// WebKit offsets start

// offsets para JSC::JSObject
export const js_cell = 0;
export const js_butterfly = 0x8;
// Início do array de propriedades inline (JSValues)
export const js_inline_prop = 0x10;

// sizeof JSC::JSObject
export const size_jsobj = js_inline_prop;

// offsets para JSC::JSArrayBufferView
export const view_m_vector = 0x10;
export const view_m_length = 0x18;
export const view_m_mode = 0x1c;

// sizeof JSC::JSArrayBufferView
export const size_view = 0x20;

// offsets para WTF::StringImpl
export const strimpl_strlen = 4;
export const strimpl_m_data = 8;
export const strimpl_inline_str = 0x14;

// sizeof WTF::StringImpl
export const size_strimpl = 0x18;

// offsets para WebCore::JSHTMLTextAreaElement, subclasse de JSObject

// offset para m_wrapped, ponteiro para um objeto DOM
// para esta classe, é um ponteiro WebCore::HTMLTextAreaElement
export const jsta_impl = 0x18;

// sizeof WebCore::JSHTMLTextAreaElement
export const size_jsta = 0x20;

// WebKit offsets end

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;
export const page_size = 16 * KB; // Tamanho da página no PS4

// Tamanho do buffer usado por setcontext/getcontext (veja module/chain.mjs)
export const context_size = 0xc8;
