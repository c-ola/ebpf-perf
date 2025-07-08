#!/bin/sh

set -x

target=$1
bname=$(basename $target)
build_dir=$2/${bname}
mkdir -p $build_dir
# Get the addresses of symbols in the binary ()
nm -U -v -S --demangle $target > ${build_dir}/${bname}.syms

# get a stripped version of the binary
strip  $target -o ${build_dir}/${bname}

# generate symbols.json
python3 scripts/symbols.py ${build_dir}/${bname}.syms ${build_dir}/${bname} ${build_dir}/symbols.json

source_dir=$3
# try and get a description of the structs in the program
ctags --c-kinds=+p --fields=+ --sort=no -o ${build_dir}/tags -R $source_dir 
python3 scripts/ctags_parse.py ${build_dir}/tags ${build_dir}/desc.json
