#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

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

#ifndef OCALL_FTELL_DEFINED__
#define OCALL_FTELL_DEFINED__
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftell, (const char* filename));
#endif
#ifndef OCALL_FREAD_DEFINED__
#define OCALL_FREAD_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fread, (const char* filename, char* buf, unsigned int size));
#endif
#ifndef OCALL_FREMOVE_DEFINED__
#define OCALL_FREMOVE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fremove, (const char* filename));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef U_SGXPROTECTEDFS_EXCLUSIVE_FILE_OPEN_DEFINED__
#define U_SGXPROTECTEDFS_EXCLUSIVE_FILE_OPEN_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_exclusive_file_open, (const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code));
#endif
#ifndef U_SGXPROTECTEDFS_CHECK_IF_FILE_EXISTS_DEFINED__
#define U_SGXPROTECTEDFS_CHECK_IF_FILE_EXISTS_DEFINED__
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_check_if_file_exists, (const char* filename));
#endif
#ifndef U_SGXPROTECTEDFS_FREAD_NODE_DEFINED__
#define U_SGXPROTECTEDFS_FREAD_NODE_DEFINED__
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fread_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
#endif
#ifndef U_SGXPROTECTEDFS_FWRITE_NODE_DEFINED__
#define U_SGXPROTECTEDFS_FWRITE_NODE_DEFINED__
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_node, (void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size));
#endif
#ifndef U_SGXPROTECTEDFS_FCLOSE_DEFINED__
#define U_SGXPROTECTEDFS_FCLOSE_DEFINED__
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fclose, (void* f));
#endif
#ifndef U_SGXPROTECTEDFS_FFLUSH_DEFINED__
#define U_SGXPROTECTEDFS_FFLUSH_DEFINED__
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fflush, (void* f));
#endif
#ifndef U_SGXPROTECTEDFS_REMOVE_DEFINED__
#define U_SGXPROTECTEDFS_REMOVE_DEFINED__
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_remove, (const char* filename));
#endif
#ifndef U_SGXPROTECTEDFS_RECOVERY_FILE_OPEN_DEFINED__
#define U_SGXPROTECTEDFS_RECOVERY_FILE_OPEN_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_recovery_file_open, (const char* filename));
#endif
#ifndef U_SGXPROTECTEDFS_FWRITE_RECOVERY_NODE_DEFINED__
#define U_SGXPROTECTEDFS_FWRITE_RECOVERY_NODE_DEFINED__
uint8_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_fwrite_recovery_node, (void* f, uint8_t* data, uint32_t data_length));
#endif
#ifndef U_SGXPROTECTEDFS_DO_FILE_RECOVERY_DEFINED__
#define U_SGXPROTECTEDFS_DO_FILE_RECOVERY_DEFINED__
int32_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxprotectedfs_do_file_recovery, (const char* filename, const char* recovery_filename, uint32_t node_size));
#endif
#ifndef OCALL_CURRENT_TIME_DEFINED__
#define OCALL_CURRENT_TIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_current_time, (double* time));
#endif
#ifndef OCALL_LOW_RES_TIME_DEFINED__
#define OCALL_LOW_RES_TIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_low_res_time, (int* time));
#endif
#ifndef OCALL_RECV_DEFINED__
#define OCALL_RECV_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int sockfd, void* buf, size_t len, int flags));
#endif
#ifndef OCALL_SEND_DEFINED__
#define OCALL_SEND_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int sockfd, const void* buf, size_t len, int flags));
#endif

sgx_status_t ecall_init_kms(sgx_enclave_id_t eid, int env);
sgx_status_t ecall_remove(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_signin(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_signout(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_signup(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_get_role(sgx_enclave_id_t eid, char* role, size_t len);
sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args);
sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args);
sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval);
sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid);
sgx_status_t enc_wolfSSL_Debugging_OFF(sgx_enclave_id_t eid);
sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, long int* retval);
sgx_status_t enc_wolfTLSv1_2_server_method(sgx_enclave_id_t eid, long int* retval);
sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, long int* retval, long int method);
sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server);
sgx_status_t enc_wolfSSL_CTX_set_cipher_list(sgx_enclave_id_t eid, int* retval, long int ctxId, const char* list);
sgx_status_t enc_wolfSSL_set_verify_client(sgx_enclave_id_t eid, int* retval, long int ctxId);
sgx_status_t enc_wolfSSL_set_verify_none(sgx_enclave_id_t eid, int* retval, long int ctxId);
sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, long int* retval, long int ctxId);
sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, long int sslId, int fd);
sgx_status_t enc_wolfSSL_accept(sgx_enclave_id_t eid, int* retval, long int sslId);
sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, long int sslId);
sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, long int sslId, const void* in, int sz);
sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, long int sslId, char* out, int sz);
sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, long int sslId, int ret);
sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, long int sslId);
sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, long int ctxId);
sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval);
sgx_status_t enc_wolfSSL_CTX_UseSupportedCurve(sgx_enclave_id_t eid, int* retval, long int ctxId);
sgx_status_t enc_wolfSSL_set_SNI(sgx_enclave_id_t eid, int* retval, long int ctxId, const char* buf);
sgx_status_t enc_wolfSSL_secure_http_read(sgx_enclave_id_t eid, int* retval, long int sslId, char* out, int sz);
sgx_status_t enc_wolfSSL_secure_http_write(sgx_enclave_id_t eid, int* retval, long int sslId, const char* in);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
