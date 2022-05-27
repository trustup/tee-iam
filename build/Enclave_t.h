#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "time.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/openssl/evp.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init_kms(int env);
int ecall_remove(void);
int ecall_signin(void);
int ecall_signout(void);
int ecall_signup(void);
void ecall_get_role(char* role, size_t len);
int wc_test(void* args);
int wc_benchmark_test(void* args);
int enc_wolfSSL_Init(void);
void enc_wolfSSL_Debugging_ON(void);
void enc_wolfSSL_Debugging_OFF(void);
long int enc_wolfTLSv1_2_client_method(void);
long int enc_wolfTLSv1_2_server_method(void);
long int enc_wolfSSL_CTX_new(long int method);
int enc_wolfSSL_CTX_use_PrivateKey_buffer(long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
int enc_wolfSSL_CTX_load_verify_buffer(long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
int enc_wolfSSL_CTX_use_certificate_buffer(long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
int enc_wolfSSL_CTX_set_cipher_list(long int ctxId, const char* list);
int enc_wolfSSL_set_verify_client(long int ctxId);
int enc_wolfSSL_set_verify_none(long int ctxId);
long int enc_wolfSSL_new(long int ctxId);
int enc_wolfSSL_set_fd(long int sslId, int fd);
int enc_wolfSSL_accept(long int sslId);
int enc_wolfSSL_connect(long int sslId);
int enc_wolfSSL_write(long int sslId, const void* in, int sz);
int enc_wolfSSL_read(long int sslId, char* out, int sz);
int enc_wolfSSL_get_error(long int sslId, int ret);
void enc_wolfSSL_free(long int sslId);
void enc_wolfSSL_CTX_free(long int ctxId);
int enc_wolfSSL_Cleanup(void);
int enc_wolfSSL_CTX_UseSupportedCurve(long int ctxId);
int enc_wolfSSL_set_SNI(long int ctxId, const char* buf);
int enc_wolfSSL_secure_http_read(long int sslId, char* out, int sz);
int enc_wolfSSL_secure_http_write(long int sslId, const char* in);

sgx_status_t SGX_CDECL ocall_ftell(unsigned int* retval, const char* filename);
sgx_status_t SGX_CDECL ocall_fread(const char* filename, char* buf, unsigned int size);
sgx_status_t SGX_CDECL ocall_fremove(const char* filename);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(void** retval, const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code);
sgx_status_t SGX_CDECL u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int32_t* retval, void* f);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* f);
sgx_status_t SGX_CDECL u_sgxprotectedfs_remove(int32_t* retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename);
sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(uint8_t* retval, void* f, uint8_t* data, uint32_t data_length);
sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(int32_t* retval, const char* filename, const char* recovery_filename, uint32_t node_size);
sgx_status_t SGX_CDECL ocall_current_time(double* time);
sgx_status_t SGX_CDECL ocall_low_res_time(int* time);
sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
