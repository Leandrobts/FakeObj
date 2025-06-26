//module/alert.mjs

// Não é possível abrir um console no navegador do PS4, então garanta que os erros
// lançados pelo programa sejam alertados.

// Não usamos uma função de log customizada para evitar uma dependência
// em um módulo de log, já que queremos que este arquivo seja autônomo.
// Também não queremos copiar a função de log aqui para evitar dependências,
// pois usar alert() é suficiente.

// Registramos também os números de linha e coluna, pois algumas exceções
// (como SyntaxError) não os mostram no stack trace.

addEventListener('unhandledrejection', event => {
    const reason = event.reason;
    alert(
        'Unhandled rejection\n'
        + `${reason}\n`
        + `${reason.sourceURL || 'N/A'}:${reason.line || 'N/A'}:${reason.column || 'N/A'}\n` // Adicionado fallback 'N/A'
        + `${reason.stack}`
    );
    event.preventDefault(); // Impede a ação padrão para o evento.
});

addEventListener('error', event => {
    const reason = event.error;
    alert(
        'Unhandled error\n'
        + `${reason}\n`
        + `${event.filename || 'N/A'}:${event.lineno || 'N/A'}:${event.colno || 'N/A'}\n` // Usando propriedades do Event
        + `${reason.stack}`
    );
    return true; // Retorna true para suprimir o erro.
});

// Temos que importar o programa dinamicamente se quisermos capturar seus
// erros de sintaxe.
// Importa o arquivo principal do exploit (psfree.mjs).
// Removido o import de psfree.mjs aqui.
// O psfree.mjs será o ponto de entrada da lógica principal do exploit kernel, se você decidir ativá-la.
// Por enquanto, o main.mjs chamará a cadeia WebKit.
// A lógica para `psfree.mjs` (o kernel exploit) será tratada quando você decidir integrá-lo.
