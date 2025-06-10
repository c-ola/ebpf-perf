#include "symbols.h"
#include "json-c/json_tokener.h"
#include "stdio.h"
#include <stdlib.h>
#include <string.h>

symbol_array load_symbols(const char* filename) {
    char * buffer = 0;
    long length;
    FILE * f = fopen (filename, "rb");

    if (f) {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc(length);
        if (buffer)
        {
            fread (buffer, 1, length, f);
        }
        fclose (f);
    }

    struct json_object* obj = json_tokener_parse(buffer);

    struct json_object* tmp_obj;
    json_object_object_get_ex(obj, "offset", &tmp_obj);
    unsigned long offset = json_object_get_uint64(tmp_obj);

    json_object_object_get_ex(obj, "symbols", &tmp_obj);
    size_t len = json_object_array_length(tmp_obj);
    struct json_object* obj_arr = tmp_obj;

    symbol_array symbols = {
        .values = malloc(sizeof(symbol) * len),
        .length = len,
        .offset = offset,
    };

    printf("%lu json_objs\n", len);
    for (size_t i = 0; i < len; i++) {
        struct json_object* obj = json_object_array_get_idx(obj_arr, i);
        struct json_object* sym_obj;

        json_object_object_get_ex(obj, "symbol", &sym_obj);
        const char* sym = json_object_get_string(sym_obj);
        size_t sym_len = json_object_get_string_len(sym_obj);

        json_object_object_get_ex(obj, "addr", &sym_obj);
        unsigned long addr = json_object_get_uint64(sym_obj);

        symbol* sym_struct = &symbols.values[i];
        memcpy((void*)sym_struct->name, sym, sym_len);
        sym_struct->addr = addr;
        printf("%s 0x%lx\n", sym_struct->name, sym_struct->addr);
    }
    free(buffer);
    return symbols;
}

const char* get_symbol_name(symbol_array* symbols, unsigned long addr) {
    for (int i = 0; i < symbols->length; i++) {
        if (symbols->values[i].addr == addr) {
            return symbols->values[i].name;
        }
    }
    return NULL;
}
