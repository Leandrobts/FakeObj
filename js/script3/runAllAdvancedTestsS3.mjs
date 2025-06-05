// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeFakeArrayBufferCraftTest } from './testFakeArrayBufferCraft.mjs'; // Atualizado

async function runCraftFakeABStrategy() { // Nome da estratégia atualizado
    const FNAME_RUNNER = "runCraftFakeABStrategy";
    logS3(`==== INICIANDO Estratégia de Construção de ArrayBuffer Falso ====`, 'test', FNAME_RUNNER);

    await executeFakeArrayBufferCraftTest();

    logS3(`==== Estratégia de Construção de ArrayBuffer Falso CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_CraftFakeAB'; // Nome do teste principal atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Construção de Estruturas Fake ArrayBuffer ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Craft Fake AB";

    await runCraftFakeABStrategy(); // Chama a nova estratégia

    logS3(`\n==== Script 3 CONCLUÍDO (Craft Fake AB) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    document.title = "Script 3 Concluído - Craft Fake AB";
}
