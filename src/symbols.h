#pragma once
#include <stddef.h>
typedef struct _symbol{
    unsigned long addr;
    char name[256];
    unsigned long * returns;
    int num_returns;
} symbol;

typedef struct {
    struct _symbol** values;
    size_t length;
    long unsigned long offset;
} symbol_array;

struct json_object;

symbol* symbol_new(unsigned long addr, const char* name, int name_len);
void symbol_add_return(symbol* sym, unsigned long * returns, int count);
void symbol_add_return_from_json(symbol* sym, struct json_object*);
void print_symbol(symbol* sym);
symbol_array load_symbols(const char* filename);

const char* get_symbol_name(symbol_array* symbols, unsigned long addr, int* is_ret);
