// main.mjs (ATUALIZADO COM LÓGICA DE BOTÕES SEPARADA)

import {
    executeExploitChain,
    testAndStabilizeCorePrimitives
} from './script3/testArrayBufferVictimCrash.mjs';
import { setLogFunction } from './module/utils.mjs';
import { JSC_OFFSETS, OFFSET_TEST_CASES } from './config.mjs';

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
const PAUSE = async (ms = 50) => {
    return new Promise(resolve => setTimeout(resolve, ms));
};

// --- Initialization Logic ---
function initializeAndRunTest() {
    const fullChainBtn = getElementById('runFullChainBtn');
    const primitivesTestBtn = getElementById('runPrimitivesTestBtn');
    const selector = getElementById('testCaseSelector');
    const outputDiv = getElementById('output-advanced');

    setLogFunction(log);

    // Popula o dropdown com os casos de teste do config.mjs
    if (selector) {
        OFFSET_TEST_CASES.forEach((testCase, index) => {
            const option = document.createElement('option');
            option.value = index;
            option.textContent = testCase.name;
            selector.appendChild(option);
        });
    }

    // Listener para o botão de teste de primitivas (DEBUG)
    if (primitivesTestBtn) {
        primitivesTestBtn.addEventListener('click', async () => {
            if (fullChainBtn.disabled || primitivesTestBtn.disabled) return;
            fullChainBtn.disabled = true;
            primitivesTestBtn.disabled = true;

            if (outputDiv) outputDiv.innerHTML = '';
            
            const selectedIndex = selector.value;
            const selectedTestCase = OFFSET_TEST_CASES[selectedIndex];
            
            log(`--- Iniciando teste de primitivas para: "${selectedTestCase.name}" ---`, 'test');
            log(`Aplicando offsets: BUTTERFLY_OFFSET=0x${selectedTestCase.offsets.BUTTERFLY_OFFSET.toString(16)}, INLINE_PROPERTIES_OFFSET=0x${selectedTestCase.offsets.INLINE_PROPERTIES_OFFSET.toString(16)}`, 'info');

            // Aplica dinamicamente os offsets selecionados
            Object.assign(JSC_OFFSETS.JSObject, selectedTestCase.offsets);
            
            try {
                await testAndStabilizeCorePrimitives(log, PAUSE);
            } catch (e) {
                console.error("Critical error during primitives test:", e);
                log(`[CRITICAL DEBUG ERROR] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n`, 'critical');
            } finally {
                log(`--- Teste de primitivas para "${selectedTestCase.name}" concluído. ---`, 'test');
                fullChainBtn.disabled = false;
                primitivesTestBtn.disabled = false;
            }
        });
    } else {
        console.error("Button 'runPrimitivesTestBtn' not found.");
    }

    // Listener para o botão da cadeia de exploit completa (PRINCIPAL)
    if (fullChainBtn) {
        fullChainBtn.addEventListener('click', async () => {
            if (fullChainBtn.disabled || primitivesTestBtn.disabled) return;
            fullChainBtn.disabled = true;
            primitivesTestBtn.disabled = true;

            if (outputDiv) outputDiv.innerHTML = '';

            // Usa a primeira configuração de offsets como padrão para a cadeia principal
            const defaultTestCase = OFFSET_TEST_CASES[0];
            log(`--- Iniciando cadeia de exploit completa com offsets padrão: "${defaultTestCase.name}" ---`, 'test');
            Object.assign(JSC_OFFSETS.JSObject, defaultTestCase.offsets);
            
            try {
                await executeExploitChain(log, PAUSE);
            } catch (e) {
                console.error("Critical error during full chain execution:", e);
                log(`[CRITICAL CHAIN ERROR] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n`, 'critical');
            } finally {
                log(`--- Cadeia de exploit completa finalizada. ---`, 'test');
                fullChainBtn.disabled = false;
                primitivesTestBtn.disabled = false;
            }
        });
    } else {
        console.error("Button 'runFullChainBtn' not found.");
    }
}

// Ensure DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAndRunTest);
} else {
    initializeAndRunTest();
}
