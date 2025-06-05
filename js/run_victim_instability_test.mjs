// js/run_victim_instability_test.mjs
import { getRunVictimTestBtn, getOutputAdvancedS3 as getOutputAdvancedDiv } from './dom_elements.mjs'; // Corrigido para usar alias se dom_elements exporta getOutputAdvancedS3
import { logS3, PAUSE_S3 } from './script3/s3_utils.mjs';
import { runAllInstabilityTestsOnVictimAB } from './script3/testJsonTypeConfusionUAFSpeculative.mjs'; // <--- ESTA É A IMPORTAÇÃO
import { selfTestOOBReadWrite, clearOOBEnvironment } from './core_exploit.mjs';

async function executeVictimInstabilityStrategy() {
    const FNAME_STRATEGY = "executeVictimInstabilityStrategy";
    logS3(`==== INICIANDO Estratégia de Teste de Instabilidade de ArrayBuffer ====`, 'test', FNAME_STRATEGY);

    await selfTestOOBReadWrite();
    await PAUSE_S3(500);

    await runAllInstabilityTestsOnVictimAB(); // <--- E ESTE É O USO

    logS3(`==== Estratégia de Teste de Instabilidade de ArrayBuffer CONCLUÍDA ====`, 'test', FNAME_STRATEGY);
}

function initializeAndRunTest() {
    const runBtn = getRunVictimTestBtn();
    const outputDiv = getOutputAdvancedDiv(); // Usa o alias ou o nome direto se corrigido em dom_elements

    if (!outputDiv) {
        console.error("DIV 'output-advanced' não encontrada. O log não será exibido na página.");
    }

    if (runBtn) {
        logS3("Botão 'runVictimTestBtn' encontrado. Aguardando clique.", "info", "main_init");
        runBtn.addEventListener('click', async () => {
            if (runBtn.disabled) return;
            runBtn.disabled = true;
            document.title = "Executando Teste AB Instability...";

            if (outputDiv) {
                outputDiv.innerHTML = '';
            }
            logS3("Iniciando teste de instabilidade de ArrayBuffer...", "test", "main_runner");

            try {
                await executeVictimInstabilityStrategy();
            } catch (e) {
                console.error("Erro crítico durante a execução do teste de instabilidade:", e);
                logS3(`ERRO CRÍTICO NO TESTE: ${e.message}${e.stack ? '\\n' + e.stack : ''}`, "critical", "main_runner");
                document.title = "ERRO CRÍTICO Teste AB Instability!";
            } finally {
                logS3("Teste de instabilidade de ArrayBuffer finalizado.", "test", "main_runner");
                 if (!document.title.includes("ERRO") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS")) {
                    document.title = "Teste AB Instability Concluído";
                 }
                runBtn.disabled = false;
                clearOOBEnvironment();
            }
        });
    } else {
        console.error("Botão 'runVictimTestBtn' não encontrado no DOM.");
        if (outputDiv) {
            logS3("Botão 'runVictimTestBtn' não encontrado.", "error", "main_init");
        }
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAndRunTest);
} else {
    initializeAndRunTest();
}
