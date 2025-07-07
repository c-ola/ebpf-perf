// https://github.com/anakryiko/bpf-ringbuf-examples/blob/main/src/ringbuf-output.c
#include "uprobe.skel.h"
#include "common.h"
#include "symbols.h"
#include <ctype.h>
#include <errno.h>
#include <json-c/json_object.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

struct handle_ctx {
    symbol_array* symbols;
    FILE* log_file;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

static bool exiting = false;
static void sig_handler(int sig)
{
    exiting = true;
}

int handle_data(void* vctx, void* dat, size_t dat_sz){
    struct handle_ctx ctx = *(struct handle_ctx*)vctx;
    struct perf_data *d = dat;
#ifdef __x86_64__
    unsigned long addr = d->ip - d->base_code_addr + ctx.symbols->offset;
#else
    unsigned long addr = d->ip - d->base_code_addr;
#endif
    int is_ret = 0;
    const char* name = get_symbol_name(ctx.symbols, addr, &is_ret);
    fprintf(ctx.log_file, is_ret ? "ret: " : "enter: ");
    fprintf(ctx.log_file, "pid=%d, name=%s, t=%lu, addr=%lx\n", d->pid, name, d->call_time, addr); 
    printf(is_ret ? "ret: " : "enter: ");
    printf("pid=%d, name=%s, t=%lu, addr=%lx\n", d->pid, name, d->call_time, addr); 
    if (!is_ret) {
        printf("arg1=0x%08lx, arg2=0x%08lx, arg3=0x%08lx, arg4=0x%08lx, arg5=0x%08lx, arg6=0x%08lx, ", d->params[0], d->params[1], d->params[2], d->params[3], d->params[4], d->params[5]);
        fprintf(ctx.log_file, "arg1=0x%08lx, arg2=0x%08lx, arg3=0x%08lx, arg4=0x%08lx, arg5=0x%08lx, arg6=0x%08lx, ", d->params[0], d->params[1], d->params[2], d->params[3], d->params[4], d->params[5]);
    } else {
        printf("ret=0x%08lx, ", d->ret);
        fprintf(ctx.log_file, "ret=0x%08lx, ", d->ret);
    }
    return 0;
}


int attach_to_symbols(symbol_array symbols, struct uprobe_bpf* skel, const char* elf_path) {
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
    for (size_t i = 0; i < symbols.funcs_len; i++) {
        symbol* sym = symbols.functions[i];
        //uprobe_opts.func_name = sym->name;
        uprobe_opts.retprobe = false;
        //uprobe_opts.attach_mode = PROBE_ATTACH_MODE_LINK; // doesn't work on armbian, maybe libbpf version is outdated?
        skel->links.uprobe_entry = bpf_program__attach_uprobe_opts(skel->progs.uprobe_entry, -1, elf_path, sym->addr, &uprobe_opts);
        printf("%s=0x%lx\n", sym->name, sym->addr);
        //char path[256] = "/sys/fs/bpf/";
        //strcat(path, uprobe_opts.func_name);
        //bpf_link__pin(skel->links.uprobe_entry, path);
        if (!skel->links.uprobe_entry) {
            fprintf(stderr, "Failed to attach uprobe: %d\n", errno);
            return errno;
        }

        for (int j = 0; j < sym->num_returns; j++) {
            //uprobe_opts.func_name = sym->name;
            uprobe_opts.retprobe = true;
            unsigned long addr = sym->returns[j];// - sym->addr;
            printf("ret=0x%lx\n", sym->returns[j]);
            //printf("attaching ret to offset 0x%lx, for ret 0x%lx\n", addr, sym->returns[i]);
            skel->links.uprobe_ret = bpf_program__attach_uprobe_opts( skel->progs.uprobe_ret, -1, elf_path, addr, &uprobe_opts);
            if (!skel->links.uprobe_ret) {
                fprintf(stderr, "Failed to attach ret uprobe: %d\n", errno);
                return errno;
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    const char* symbols_path = "symbols.json";
    const char* elf_path = NULL;
    const char* log_path = "log.trace";
    int c; opterr = 0;
    if (argc == 0) {
        fprintf (stderr, "please provide arguments:\nusage: uprobe [ARGS]\n\t-e <elf_path>\n\t-s <symbols_path>\n");
    }
    while ((c = getopt(argc, argv, ":e:s:o:")) != -1) {
        switch (c) {
            case 'e':
                elf_path = optarg;
                break;
            case 's':
                symbols_path = optarg;
                break;
            case 'o':
                log_path = optarg;
                break;
            case ':':
                if (optopt == 'e')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                return 1;
            case '?':
                if (optopt == 'e')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (optopt == 'h')
                    fprintf (stderr, "usage: uprobe [ARGS]\n\t-e <elf_path>\n\t-s <symbols_path>\n\t -o <log_path>\n");
                else if (isprint(optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default:
                abort();
        }
    }

    if (elf_path == NULL) {
        fprintf(stderr, "Option -e <elf_path> is required\n");
        return 1;
    }

    printf("Start monitoring for elf %s. Using symbols s:%s\n", elf_path, symbols_path);
    struct uprobe_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    symbol_array symbols = load_symbols(symbols_path);
    printf("Found %ld functions symbols\n", symbols.funcs_len);
    for (size_t i = 0; i < symbols.funcs_len; i++) {
        print_symbol(symbols.functions[i]);
    }
    printf("Found %ld global symbols\n", symbols.globals_len);
    for (size_t i = 0; i < symbols.globals_len; i++) {
        print_symbol(symbols.globals[i]);
    }

    // pin the bpf program so it still exist when this program exits, idk how this works yet
    //bpf_program__pin(skel->progs.uprobe_entry, "/sys/fs/bpf/uprobe_entry");
    err = attach_to_symbols(symbols, skel, elf_path);
    if (err != 0) {
        fprintf(stderr, "Failed to attach bpf prog to symbols: %d\n", errno);
        return -1;
    }

    /* Attach tracepoint handler */
    struct handle_ctx ctx;
    ctx.symbols = &symbols;
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_data, &ctx, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        clear_symbol_array(symbols);
        uprobe_bpf__destroy(skel);
        return -1;
    }
    ctx.log_file = fopen(log_path, "w");
    if (!ctx.log_file) {
        perror("Failed to open specified log file");
        ring_buffer__free(rb);
        clear_symbol_array(symbols);
        uprobe_bpf__destroy(skel);
        return -1;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` " "to see output of the BPF programs.\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }
    fclose(ctx.log_file);
    ring_buffer__free(rb);
    clear_symbol_array(symbols);
    uprobe_bpf__destroy(skel);
    return -err;
}
