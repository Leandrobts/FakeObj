// main.mjs (Atualizado para o novo sistema de teste)

import {
    executeExploitChain,
    testAndStabilizeCorePrimitives, // IMPORTADA NOVA FUNÇÃO DE TESTE
    FNAME_MODULE
} from './script3/testArrayBufferVictimCrash.mjs';
// Apenas importar setLogFunction e toHex de utils.mjs, pois log é declarado localmente.
import { setLogFunction, toHex } from './module/utils.mjs';
import { Int } from './module/int64.mjs';


// --- Local DOM Elements Management ---
const elementsCache = {};

function getElementById(id) {
    if (elementsCache[id] && document.body.contains(elementsCache[id])) {
        return elementsCache[id];
    }
    const element = document.getElementById(id);
    if (element) {
        elementsCache[id] = element;
    }
    return element;
}

// --- Local Logging Functionality ---
const outputDivId = 'output-advanced';

// Esta é a declaração principal da função log
export const log = (message, type = 'info', funcName = '') => {
    const outputDiv = getElementById(outputDivId);
    if (!outputDiv) {
        console.error(`Log target div "${outputDivId}" not found. Message: ${message}`);
        return;
    }
    try {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const prefix = funcName ? `[${funcName}] ` : '';
        const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool', 'debug'].includes(type) ? type : 'info';

        if (outputDiv.innerHTML.length > 600000) {
            const lastPart = outputDiv.innerHTML.substring(outputDiv.innerHTML.length - 300000);
            outputDiv.innerHTML = `<span class="log-info">[${new Date().toLocaleTimeString()}] [Log Truncado...]</span>\n` + lastPart;
        }

        outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${sanitizedMessage}\n</span>`;
        outputDiv.scrollTop = outputDiv.scrollHeight;
    } catch (e) {
        console.error(`Error in logToDiv for ${outputDivId}:`, e, "Original message:", message);
        if (outputDiv) outputDiv.innerHTML += `[${new Date().toLocaleTimeString()}] [LOGGING ERROR] ${String(e)}\n`;
    }
};

// --- Local Pause Functionality ---
const SHORT_PAUSE = 50;
const MEDIUM_PAUSE = 500;
const LONG_PAUSE = 1000;

const PAUSE = async (ms = SHORT_PAUSE) => {
    return new Promise(resolve => setTimeout(resolve, ms));
};

// --- JIT Behavior Test ---
async function testJITBehavior() {
    log("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'testJITBehavior');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 };

    log("Escrevendo um objeto em um Float64Array...", 'info', 'testJITBehavior');
    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    const leaked_val = new Int(low, high);

    log(`Bits lidos: high=0x${high.toString(16)}, low=0x${low.toString(16)} (Valor completo: ${leaked_val.toString(true)})`, 'leak', 'testJITBehavior');

    if (high === 0x7ff80000 && low === 0) {
        log("CONFIRMADO: O JIT converteu o objeto para NaN, como esperado.", 'good', 'testJITBehavior');
    } else {
        log("INESPERADO: O JIT não converteu para NaN. O comportamento é diferente do esperado.", 'warn', 'testJITBehavior');
    }
    log("--- Teste de Comportamento do JIT Concluído ---", 'test', 'testJITBehavior');
}


// --- Initialization Logic ---
function initializeAndRunTest() {
    const runBtn = getElementById('runIsolatedTestBtn');
    const stabilizationBtn = getElementById('runStabilizationTestBtn'); // NOVO BOTÃO
    const outputDiv = getElementById('output-advanced');

    setLogFunction(log);

    if (!outputDiv) {
        console.error("DIV 'output-advanced' not found. Log will not be displayed on the page.");
    }

    if (runBtn) {
        runBtn.addEventListener('click', async () => {
            if (runBtn.disabled || stabilizationBtn.disabled) return;
            runBtn.disabled = true;
            stabilizationBtn.disabled = true;

            if (outputDiv) outputDiv.innerHTML = '';
            console.log("Starting full exploit chain");

            try {
                await testJITBehavior();
                await PAUSE(MEDIUM_PAUSE);
                await executeExploitChain(log, PAUSE);
            } catch (e) {
                console.error("Critical error during full exploit execution:", e);
                log(`[CRITICAL TEST ERROR] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n`, 'critical');
            } finally {
                console.log("Full exploit chain concluded.");
                log("Full exploit chain finished.\n", 'test');
                runBtn.disabled = false;
                stabilizationBtn.disabled = false;
            }
        });
    } else {
        console.error("Button 'runIsolatedTestBtn' not found.");
    }

    // LÓGICA PARA O NOVO BOTÃO DE TESTE DE ESTABILIZAÇÃO
    if (stabilizationBtn) {
        stabilizationBtn.addEventListener('click', async () => {
            if (runBtn.disabled || stabilizationBtn.disabled) return;
            runBtn.disabled = true;
            stabilizationBtn.disabled = true;

            if (outputDiv) outputDiv.innerHTML = '';
            console.log("Starting core primitive stabilization test");

            try {
                await testAndStabilizeCorePrimitives(log, PAUSE);
            } catch (e) {
                console.error("Critical error during stabilization test:", e);
                log(`[CRITICAL STABILIZATION ERROR] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n`, 'critical');
            } finally {
                console.log("Stabilization test concluded.");
                log("Stabilization test finished.\n", 'test');
                runBtn.disabled = false;
                stabilizationBtn.disabled = false;
            }
        });
    } else {
        console.error("Button 'runStabilizationTestBtn' not found.");
    }
}

// Ensure DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAndRunTest);
} else {
    initializeAndRunTest();
}
