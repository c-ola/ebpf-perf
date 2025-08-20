#include <link.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

void hook_function(void* target, void* hook) {
}

static int find_main_text_segment(struct dl_phdr_info *info, size_t size, void *data) {
    if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0') {
        printf("[*] Main binary base address: %p\n", (void*)info->dlpi_addr);

        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
            if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X)) {
                uintptr_t text_start = info->dlpi_addr + phdr->p_vaddr;
                uintptr_t text_end   = text_start + phdr->p_memsz;

                printf("[+] .text segment of main binary: %p - %p (%lx bytes)\n", (void*)text_start, (void*)text_end, phdr->p_memsz);
                uintptr_t* data_text_start = (uintptr_t*)data;
                *data_text_start = text_start;
                break;
            }
        }
    }

    return 0;
}

typedef int (*foo_t)(int, float);

__attribute__((constructor))
int so_main() {
    uintptr_t text_start;
    dl_iterate_phdr(find_main_text_segment, (void*)&text_start);
    printf("%p, 0x%lx\n", so_main, text_start);
    foo_t fooptr;
    fooptr = (foo_t)(text_start + 4425 - 4096);
    printf("fooptr=%p\n", fooptr);
    fooptr(100, 1000.0);
    return 0;
}

