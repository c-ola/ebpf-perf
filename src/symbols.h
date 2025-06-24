#pragma once
#include <stddef.h>

typedef enum symbol_type {
    SYM_FUNC,
    SYM_GLOBAL,
} symbol_type;


struct json_object;

typedef struct _symbol {
    unsigned long addr;
    char name[256];
    enum symbol_type type;
    unsigned long * returns;
    int num_returns;
} symbol;

symbol* symbol_new(unsigned long addr, const char* name, int name_len, enum symbol_type type);
void symbol_add_return(symbol* sym, unsigned long * returns, int count);
void symbol_add_return_from_json(symbol* sym, struct json_object*);
void print_symbol(symbol* sym);
void free_symbol(symbol* sym);

// this struct holds references to each symbol in an array, this is like this because symbols can have dynamic length return lists
// could probably just make it an array of pointers to them lol
typedef struct symbol_array {
    struct _symbol** functions;
    size_t funcs_len;
    struct _symbol** globals;
    size_t globals_len;
    unsigned long offset;
} symbol_array;

symbol_array load_symbols(const char* filename);

// symbol array is stored on the stack, so pass it by copy
// this function then frees and clears functions and globals symbols
void clear_symbol_array(symbol_array symbol_arr);
const char* get_symbol_name(symbol_array* symbols, unsigned long addr, int* is_ret);
