// js/script3/testAdvancedPP.mjs
// VERSÃO FINAL: O "CALDEIRÃO" DE UAF - MODO CAOS

import { logS3, PAUSE_S3 } from './s3_utils.mjs';

const POOL_SIZE = 5000;
const CAULDRON_DURATION_MS = 20000; // Deixe o caos reinar por 20 segundos

/**
 * Cria um ambiente caótico com múltiplos loops assíncronos competindo por um pool
 * de objetos compartilhado para forçar uma condição de Use-After-Free.
 */
export async function runChaoticUAFCauldron() {
    const FNAME = 'ChaoticUAFCauldron';
    logS3(`--- MODO CAOS: Iniciando o Caldeirão de UAF ---`, 'test', FNAME);
    logS3(`Duração: ${CAULDRON_DURATION_MS / 1000} segundos. O navegador pode não responder.`, 'critical', FNAME);

    const originalCallDescriptor = Object.getOwnPropertyDescriptor(Function.prototype, 'call');
    const victimPool = new Array(POOL_SIZE).fill(null);
    let intervals = [];
    let chaosWorker;
    let stats = { allocations: 0, frees: 0, uses: 0, potential_uaf: 0 };

    try {
        // O Hijack de 'call' agora é mais ativo: ele tenta escrever na propriedade do objeto.
        // Escrever em memória liberada é muito mais propenso a causar um crash do que ler.
        const hijackFunction = function() {
            stats.uses++;
            if (this && typeof this === 'object' && this.id) {
                // Tentativa de escrita. Se 'this' for um ponteiro inválido, CRASH!
                this.id = -1; 
            }
        };
        Object.defineProperty(Function.prototype, 'call', { value: hijackFunction, configurable: true });

        // 5. O TRABALHADOR DO CAOS
        const workerScript = `
            let memoryHog = [];
            setInterval(() => {
                // Aloca e libera memória para estressar o GC de outro thread
                for(let i=0; i<100; i++) {
                    memoryHog.push(new Uint8Array(1024));
                }
                if (memoryHog.length > 500) {
                    memoryHog = [];
                }
            }, 50);
        `;
        chaosWorker = new Worker(URL.createObjectURL(new Blob([workerScript])));
        logS3('Trabalhador do Caos (Chaos Worker) iniciado.', 'warn', FNAME);

        // 2. O ALOCADOR
        intervals.push(setInterval(() => {
            const index = Math.floor(Math.random() * POOL_SIZE);
            if (victimPool[index] === null) {
                victimPool[index] = { id: index, payload: new Uint8Array(Math.random() * 512) };
                stats.allocations++;
            }
        }, 13)); // Frequências com números primos evitam sincronização

        // 3. O LIBERADOR
        intervals.push(setInterval(() => {
            const index = Math.floor(Math.random() * POOL_SIZE);
            if (victimPool[index] !== null) {
                victimPool[index] = null; // Libera o objeto
                stats.frees++;
            }
        }, 17));

        // 4. O USADOR
        intervals.push(setInterval(() => {
            const index = Math.floor(Math.random() * POOL_SIZE);
            const victim = victimPool[index];
            if (victim) {
                // Acessa o objeto. Se o Liberador agiu entre a leitura de 'victim'
                // e esta linha, temos uma condição de corrida.
                try {
                    Object.keys.call(victim);
                } catch(e) {
                    stats.potential_uaf++;
                }
            }
        }, 7));
        
        logS3('Caldeirão ativado. Todos os loops estão em execução...', 'critical', FNAME);

        // Aguarda a duração do teste
        await PAUSE_S3(CAULDRON_DURATION_MS);

    } catch (e) {
        logS3(`ERRO CRÍTICO durante o setup do Caldeirão: ${e.message}`, 'error', FNAME);
    } finally {
        logS3('Finalizando o Caldeirão. Limpando timers e worker...', 'info', FNAME);
        intervals.forEach(clearInterval);
        if (chaosWorker) chaosWorker.terminate();
        if (originalCallDescriptor) {
            Object.defineProperty(Function.prototype, 'call', originalCallDescriptor);
        }
        logS3('Estatísticas do Caldeirão:', 'info', FNAME);
        logS3(`  - Alocações: ${stats.allocations}`, 'info', FNAME);
        logS3(`  - Liberações: ${stats.frees}`, 'info', FNAME);
        logS3(`  - Usos (chamadas sequestradas): ${stats.uses}`, 'info', FNAME);
        logS3(`  - Potenciais UAFs (erros de acesso): ${stats.potential_uaf}`, 'warn', FNAME);
    }
}
