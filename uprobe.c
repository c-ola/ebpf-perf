// https://github.com/anakryiko/bpf-ringbuf-examples/blob/main/src/ringbuf-output.c
#include <errno.h>
#include <json-c/json_object.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"
#include "json-c/json_tokener.h"

typedef struct {
    unsigned long addr;
    char name[256];
} symbol;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

struct data {
    pid_t pid;
    unsigned long call_time;
    unsigned long ip;
};

void load_symbols() {
    const char* filename = "symbols.json";
    char * buffer = 0;
    long length;
    FILE * f = fopen (filename, "rb");

    if (f)
    {
      fseek (f, 0, SEEK_END);
      length = ftell (f);
      fseek (f, 0, SEEK_SET);
      buffer = malloc (length);
      if (buffer)
      {
        fread (buffer, 1, length, f);
      }
      fclose (f);
    }
    struct json_object* obj = json_tokener_parse(buffer);
    json_object_get_array(const struct json_object *obj)
}


static bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}

int handle_data(void* ctx, void* dat, size_t dat_sz){
    struct data *d = dat;
    printf("pid=%d, t=%lu, ip=%lx\n", d->pid, d->call_time, d->ip);
    return 0;
}

int main(int argc, char **argv)
{
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
    const char* binary_name = "./test_program";
	uprobe_opts.func_name = "foo";
	uprobe_opts.retprobe = false;
	skel->links.uprobe_entry = bpf_program__attach_uprobe_opts(skel->progs.uprobe_entry,
								 -1 /* self pid */, binary_name,
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_entry) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	uprobe_opts.func_name = "foo";
	uprobe_opts.retprobe = false;
	skel->links.uprobe_entry = bpf_program__attach_uprobe_opts(skel->progs.uprobe_entry,
								 -1 /* self pid */, binary_name,
								 0x50 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_entry) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/*uprobe_opts.func_name = "foo";
	uprobe_opts.retprobe = true;
	skel->links.uprobe_ret = bpf_program__attach_uprobe_opts(
        skel->progs.uprobe_ret,
		-1,
        binary_name,
        0x56,
        &uprobe_opts
    );
	if (!skel->links.uprobe_ret) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}*/


    /*err = uprobe_bpf__attach(skel);
      if (err) {
      fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
      goto cleanup;
      }*/


    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_data, NULL, NULL);
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
    uprobe_bpf__destroy(skel);
    return -err;
}
