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
    long unsigned long addr = d->ip - d->base_code_addr + ctx.symbols->offset;
#else
    long unsigned long addr = d->ip - d->base_code_addr;
#endif
    int is_ret = 0;
    const char* name = get_symbol_name(ctx.symbols, addr, &is_ret);
    fprintf(ctx.log_file, is_ret ? "ret: " : "enter: ");
    fprintf(ctx.log_file, "pid=%d, name=%s, t=%llu, addr=%llx\n", d->pid, name, d->call_time, addr); 
    printf(is_ret ? "ret: " : "enter: ");
    printf("pid=%d, name=%s, t=%llu, addr=%llx\n", d->pid, name, d->call_time, addr); 
    return 0;
}


int main(int argc, char **argv) {
    const char* symbols_path = "symbols.json";
    const char* elf_path = NULL;
    int c; opterr = 0;
    if (argc == 0) {
        fprintf (stderr, "please provide arguments:\nusage: uprobe [ARGS]\n\t-e <elf_path>\n\t-s <symbols_path>\n");
    }
    while ((c = getopt(argc, argv, ":e:s:")) != -1) {
        switch (c) {
            case 'e':
                elf_path = optarg;
                break;
            case 's':
                printf("%s here\n", optarg);
                symbols_path = optarg;
                break;
            case ':':
                if (optopt == 'e')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                return 1;
            case '?':
                if (optopt == 'e')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (optopt == 'h')
                    fprintf (stderr, "usage: uprobe [ARGS]\n\t-e <elf_path>\n\t-s <symbols_path>\n");
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
    symbol_array symbols = load_symbols(symbols_path);
    for (int i = 0; i < symbols.length; i++) {
        print_symbol(symbols.values[i]);
    }
    struct uprobe_bpf *skel;
    int err;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // pin the bpf program so it still exist when this program exits, idk how this works yet
    //bpf_program__pin(skel->progs.uprobe_entry, "/sys/fs/bpf/uprobe_entry");

    /* Attach tracepoint handler */
    const char* binary_name = elf_path;
    for (int i = 0; i < symbols.length; i++) {
        symbol* sym = symbols.values[i];
        //uprobe_opts.func_name = sym->name;
        uprobe_opts.retprobe = false;
        //uprobe_opts.attach_mode = PROBE_ATTACH_MODE_LINK; // doesn't work on armbian, maybe libbpf version is outdated?
        skel->links.uprobe_entry = bpf_program__attach_uprobe_opts(skel->progs.uprobe_entry, -1, binary_name, sym->addr, &uprobe_opts);
        printf("%s=0x%lx\n", sym->name, sym->addr);
        //char path[256] = "/sys/fs/bpf/";
        //strcat(path, uprobe_opts.func_name);
        //bpf_link__pin(skel->links.uprobe_entry, path);
        if (!skel->links.uprobe_entry) {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }

        for (int j = 0; j < sym->num_returns; j++) {
            //uprobe_opts.func_name = sym->name;
            uprobe_opts.retprobe = true;
            unsigned long addr = sym->returns[j];// - sym->addr;
            printf("ret=0x%lx\n", sym->returns[j]);
            //printf("attaching ret to offset 0x%lx, for ret 0x%lx\n", addr, sym->returns[i]);
            skel->links.uprobe_ret = bpf_program__attach_uprobe_opts( skel->progs.uprobe_ret, -1, binary_name, addr, &uprobe_opts);
            if (!skel->links.uprobe_ret) {
                err = -errno;
                fprintf(stderr, "Failed to attach ret uprobe: %d\n", err);
                goto cleanup;
            }
        }
    }

    struct handle_ctx ctx;
    ctx.symbols = &symbols;
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_data, &ctx, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    ctx.log_file = fopen("perf_log.log", "w");

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

cleanup:
    free(symbols.values);
    // need to free each symbol too lol, its leaking memory rn
    uprobe_bpf__destroy(skel);
    return -err;
}
