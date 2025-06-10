// https://github.com/anakryiko/bpf-ringbuf-examples/blob/main/src/ringbuf-output.c
#include "uprobe.skel.h"
#include "common.h"
#include "symbols.h"
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
    long unsigned long addr = d->ip - d->base_code_addr + ctx.symbols->offset;
    const char* name = get_symbol_name(ctx.symbols, addr);
    printf("pid=%d, name=%s, t=%llu, addr=%llx\n", d->pid, name, d->call_time, addr); 
    return 0;
}

int main(int argc, char **argv) {
    symbol_array symbols = load_symbols("build/symbols.json");
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

    /* Attach tracepoint handler */
    const char* binary_name = "./build/test";
    for (int i = 0; i < symbols.length; i++) {
        symbol* sym = &symbols.values[i];
        uprobe_opts.func_name = sym->name;
        uprobe_opts.retprobe = false;
        skel->links.uprobe_entry = bpf_program__attach_uprobe_opts(skel->progs.uprobe_entry, -1, binary_name, 0, &uprobe_opts);
        if (!skel->links.uprobe_entry) {
            err = -errno;
            fprintf(stderr, "Failed to attach uprobe: %d\n", err);
            goto cleanup;
        }
    }
    /*uprobe_opts.func_name = "foo";
      uprobe_opts.retprobe = true;
      skel->links.uprobe_ret = bpf_program__attach_uprobe_opts( skel->progs.uprobe_ret, -1, binary_name, 0x56, &uprobe_opts);
      if (!skel->links.uprobe_ret) {
      err = -errno;
      fprintf(stderr, "Failed to attach uprobe: %d\n", err);
      goto cleanup;
      }*/

    struct handle_ctx ctx;
    ctx.symbols = &symbols;
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_data, &ctx, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
            "to see output of the BPF programs.\n");
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


cleanup:
    ring_buffer__free(rb);
    free(symbols.values);
    uprobe_bpf__destroy(skel);
    return -err;
}
