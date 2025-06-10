#pragma once
#include <stddef.h>
typedef struct {
    unsigned long addr;
    char name[256];
} symbol;

typedef struct {
    symbol* values;
    size_t length;
    long unsigned long offset;
} symbol_array;

symbol_array load_symbols(const char* filename);
const char* get_symbol_name(symbol_array* symbols, unsigned long addr);
