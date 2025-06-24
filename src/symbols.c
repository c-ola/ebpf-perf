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
        buffer = (char*)malloc(length + 1);
        if (buffer) {
            fread (buffer, 1, length, f);
        }
        buffer[length] = '\0';
        fclose (f);
    }

    struct json_object* obj = json_tokener_parse(buffer);

    struct json_object* tmp_obj;
    json_object_object_get_ex(obj, "offset", &tmp_obj);
    unsigned long offset = json_object_get_uint64(tmp_obj);

    json_object_object_get_ex(obj, "functions", &tmp_obj);
    size_t len_funcs = json_object_array_length(tmp_obj);
    struct json_object* obj_arr = tmp_obj;

    json_object_object_get_ex(obj, "globals", &tmp_obj);
    size_t len_globals = json_object_array_length(tmp_obj);
    struct json_object* obj_arr_globals = tmp_obj;

    symbol_array symbols = {
        .functions = malloc(sizeof(symbol*) * len_funcs),
        .funcs_len = len_funcs,
        .globals = malloc(sizeof(symbol*) * len_globals),
        .globals_len = len_globals,
        .offset = offset,
    };

    printf("%lu json_objs\n", len_funcs);
    for (size_t i = 0; i < len_funcs; i++) {
        struct json_object* obj = json_object_array_get_idx(obj_arr, i);
        struct json_object* sym_obj, * rets_obj;

        json_object_object_get_ex(obj, "label", &sym_obj);
        const char* sym_name = json_object_get_string(sym_obj);
        size_t sym_len = json_object_get_string_len(sym_obj);

        json_object_object_get_ex(obj, "addr", &sym_obj);
        unsigned long addr = json_object_get_uint64(sym_obj);

        json_object_object_get_ex(obj, "returns", &rets_obj);
        struct _symbol* sym_struct = symbol_new(addr, sym_name, sym_len, SYM_FUNC);
        symbol_add_return_from_json(sym_struct, rets_obj);
        symbols.functions[i] = sym_struct;
    }

    for (size_t i = 0; i < len_globals; i++) {
        struct json_object* obj = json_object_array_get_idx(obj_arr_globals, i);
        struct json_object* sym_obj;

        json_object_object_get_ex(obj, "label", &sym_obj);
        const char* sym_name = json_object_get_string(sym_obj);
        size_t sym_len = json_object_get_string_len(sym_obj);

        json_object_object_get_ex(obj, "addr", &sym_obj);
        unsigned long addr = json_object_get_uint64(sym_obj);
        struct _symbol* sym_struct = symbol_new(addr, sym_name, sym_len, SYM_GLOBAL);
        symbols.globals[i] = sym_struct;
    }
    json_object_put(obj);
    free(buffer);
    return symbols;
}

symbol* symbol_new(unsigned long addr, const char *name, int name_len, enum symbol_type type) {
    symbol* sym = (symbol*) malloc(sizeof(symbol));
    sym->addr = addr;
    memset(sym->name, 0, 256);
    memcpy((void*)sym->name, name, name_len);
    sym->type = type;
    sym->num_returns = 0;
    sym->returns = NULL;
    return sym;
}

void symbol_add_return(symbol* sym, unsigned long *returns, int count) {
    if (sym->returns == NULL && sym->num_returns == 0) {
        sym->returns = malloc(sizeof(unsigned long) * count);
        memcpy((void*)sym->returns, returns, sizeof(unsigned long) * count);
        sym->num_returns = count;
    } else {
        size_t new_size = sizeof(unsigned long) * (count + sym->num_returns);
        size_t old_size = sizeof(unsigned long) * sym->num_returns;
        sym->returns = realloc(sym->returns, new_size);
        memcpy(sym->returns + old_size, returns, sizeof(unsigned long) * count);
    }
}

void symbol_add_return_from_json(symbol *sym, struct json_object * obj) {
    int num_rets = json_object_array_length(obj);
    sym->returns = malloc(sizeof(unsigned long) * num_rets);
    for (int i = 0; i < num_rets; i++) {
        struct json_object* ret_obj = json_object_array_get_idx(obj, i);
        unsigned long addr = json_object_get_uint64(ret_obj);
        sym->returns[i] = addr;
    }
    sym->num_returns = num_rets;
}

void print_symbol(symbol* sym) {
    printf("%s, 0x%lx, {", sym->name, sym->addr);
    for (int i = 0; i < sym->num_returns; i++) {
        printf("0x%lx", sym->returns[i]);
        if (i != sym->num_returns - 1) {
            printf(", ");
        }
    }
    printf("}\n");
}

void free_symbol(symbol* sym) {
    if (sym->num_returns > 0) {
        free(sym->returns);
    }
    free(sym);
}



void clear_symbol_array(symbol_array symbol_arr) {
    for (size_t i = 0; i < symbol_arr.funcs_len; i++) {
        free_symbol(symbol_arr.functions[i]);
    }
    symbol_arr.funcs_len = 0;
    for (size_t i = 0; i < symbol_arr.globals_len; i++) {
        free_symbol(symbol_arr.globals[i]);
    }
    symbol_arr.globals_len = 0;
    free(symbol_arr.functions);
    free(symbol_arr.globals);
}

const char* get_symbol_name(symbol_array* symbols, unsigned long addr, int* is_ret) {
    for (size_t i = 0; i < symbols->funcs_len; i++) {
        symbol* sym = symbols->functions[i];
        if (sym->addr == addr) {
            *is_ret = 0;
            return sym->name;
        }
        for (int j = 0; j < sym->num_returns; j++) {
            if (sym->returns[j] == addr) {
                *is_ret = 1;
                return sym->name;
            }
        }
    }
    for (size_t i = 0; i < symbols->globals_len; i++) {
        symbol* sym = symbols->globals[i];
        if (sym->addr == addr) {
            *is_ret = 2;
            return sym->name;
        }
    }
    fprintf(stderr, "Could not find symbol with addr addr 0x%lx\n", addr);
    return NULL;
}
