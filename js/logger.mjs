// js/logger.mjs
import { getElementById } from './dom_elements.mjs';

export function logToDiv(divId, message, type = 'info', funcName = '') {
    const outputDiv = getElementById(divId);
    if (!outputDiv) {
        console.error(`Log target div "${divId}" not found. Message: ${message}`);
        return;
    }
    try {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const prefix = funcName ? `[${funcName}] ` : '';
        // Basic sanitization, consider a more robust library for production
        const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool'].includes(type) ? type : 'info';

        // Log truncation logic
        if(outputDiv.innerHTML.length > 600000){ 
            const lastPart = outputDiv.innerHTML.substring(outputDiv.innerHTML.length - 300000);
            outputDiv.innerHTML = `<span class="log-info">[${new Date().toLocaleTimeString()}] [Log Truncado...]</span>\n` + lastPart;
        }

        outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${sanitizedMessage}\n</span>`;
        outputDiv.scrollTop = outputDiv.scrollHeight;
    } catch(e) { 
        console.error(`Error in logToDiv for ${divId}:`, e, "Original message:", message); 
        if (outputDiv) outputDiv.innerHTML += `[${new Date().toLocaleTimeString()}] [LOGGING ERROR] ${String(e)}\n`; 
    }
}
