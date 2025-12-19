/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <utility>
#include <unistd.h>
#include <linux/limits.h> 
#include "Enclave_u.h"
#include "sgx_urts.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define MAX_PATH 1024

#define TEST_OCALL_API 0

sgx_enclave_id_t global_eid = 0;

sgx_enclave_id_t
pal_get_enclave_id(void)
{
    return global_eid;
}

std::string get_exe_path() {
    std::string path_buf(PATH_MAX, '\0');
    ssize_t size = readlink("/proc/self/exe", &path_buf[0], PATH_MAX - 1);
    if (size < 0 || (size >= PATH_MAX - 1)) {
        return "";
    }
    path_buf.resize(size);
    size_t last_slash = path_buf.find_last_of('/');
    if (last_slash != std::string::npos) {
        path_buf.resize(last_slash + 1);
    }
    return path_buf;
}

static int
initialize_enclave()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    std::string enclave_path = get_exe_path() + std::string(ENCLAVE_FILENAME);
    ret = sgx_create_enclave(enclave_path.c_str(), SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("init enclave failed\n");
        return -1;
    }

    return 0;
}

void ocall_abort(){
    abort();
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
    fflush(stdout);
}

void ocall_getline(char *cmd, size_t cmd_size, int *n, size_t *len) 
{   
    char *c;
    ssize_t nn;
    size_t nlen = 0;
    nn = getline(&c, &nlen, stdin);
    memcpy(cmd, c, nn);
    free(c);

    *n = nn;
    *len = nlen;
}

void ocall_free_getline(char *ptr) {
    free(ptr);
}

char *load_wasm_file(const char *path, size_t &size)
{
    std::ifstream file(path, std::ios::ate);
    if (!file.is_open()) {
        return NULL;
    }
    std::streamsize file_size = file.tellg();
    char* content = (char*)malloc(file_size);
    if (!content) {
        return NULL;
    }

    file.seekg(0, std::ios::beg);
    if (!file.read(content, file_size)) {
        file.close();
        free(content);
        return NULL;
    }
    file.close();
    size = file_size;
    return content;
}

int SGX_CDECL main(int argc, char *argv[])
{
    /* Load wasm file */
    if (argc < 2) {
        printf("Please set wasm path and params\n");
        return -1; 
    }
    char *wasm_path = argv[1];
    char *wasm_buffer = NULL;
    size_t wasm_size = 0;
    wasm_buffer = load_wasm_file(wasm_path, wasm_size);
    if (wasm_buffer == nullptr || !wasm_size) {
        printf("Load wasm file failure : unexpected end\n");
        return 0; 
    }
    std::string str = std::to_string(wasm_size);
    argv[argc++] = wasm_buffer;
    argv[argc++] = const_cast<char*>(str.c_str());

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        free(wasm_buffer);
        printf("Enter a character before exit ...\n");
        return -1; 
    }

    /* Call func in SGX */
    int retval = 0;
    ecall_main(global_eid, &retval, argc, argv);

    free(wasm_buffer);
    return 0;
}