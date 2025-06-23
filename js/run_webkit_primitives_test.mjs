// js/run_webkit_primitives_test.mjs
import { getElementById } from './dom_elements.mjs'; // Para interagir com o botão e a div
import { runWebKitBaseFinderTests } from './webkit_primitives.mjs'; // Importa a função principal
import { logS3 } from './script3/s3_utils.mjs'; // Ou seu logger preferido

// Função para configurar o logger específico para esta saída, se necessário
// Se logS3 já loga para 'output-advanced', você pode querer um novo logger
// ou modificar logS3 para aceitar um ID de div dinâmico.
// Por simplicidade, vamos assumir que podemos direcionar o log ou usar o console.

function initializeAndRun() {
    const runBtn = getElementById('runWebKitPrimitivesBtn');
    const outputDiv = getElementById('output-webkit-primitives'); // Opcional, se quiser logar na div

    if (!runBtn) {
        console.error("Botão 'runWebKitPrimitivesBtn' não encontrado.");
        if (outputDiv) outputDiv.innerHTML = "<span class='log-error'>Botão não encontrado.</span>";
        return;
    }

    // Se você quiser usar a div 'output-webkit-primitives' para o logS3,
    // você precisaria ajustar logS3 ou criar uma nova função de log.
    // Exemplo: const logWebKit = (msg, type, func) => logToDiv('output-webkit-primitives', msg, type, func);
    // E passar logWebKit para runWebKitBaseFinderTests se ele aceitar um logger.
    // No script webkit_primitives.mjs, ele usa logS3 (que por padrão loga em 'output-advanced').
    // Para este exemplo, vamos assumir que o log de webkit_primitives.mjs irá para onde logS3 aponta.

    logS3("Botão 'runWebKitPrimitivesBtn' encontrado e pronto.", "info", "WebKitPrimitivesInit");

    runBtn.addEventListener('click', async () => {
        if (runBtn.disabled) return;
        runBtn.disabled = true;
        document.title = "Executando Primitivas WebKit...";

        if (outputDiv) {
            outputDiv.innerHTML = ''; // Limpa logs anteriores desta div
        }
        // Log inicial para a div específica (se estiver usando) ou para o log principal
        logS3("Iniciando execução de runWebKitBaseFinderTests...", "test", "WebKitPrimitivesRunner");

        try {
            await runWebKitBaseFinderTests(); // Chama a função principal do seu novo script
        } catch (e) {
            console.error("Erro crítico durante a execução de runWebKitBaseFinderTests:", e);
            logS3(`ERRO CRÍTICO GERAL: ${e.message}${e.stack ? '\\n' + e.stack : ''}`, "critical", "WebKitPrimitivesRunner");
            document.title = "ERRO - Primitivas WebKit";
        } finally {
            logS3("Execução de runWebKitBaseFinderTests finalizada.", "test", "WebKitPrimitivesRunner");
            if (!document.title.includes("ERRO")) {
                document.title = "Primitivas WebKit - Concluído";
            }
            runBtn.disabled = false;
        }
    });
}

// Garante que o DOM esteja pronto
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAndRun);
} else {
    initializeAndRun();
}
