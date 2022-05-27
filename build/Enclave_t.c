#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_init_kms_t {
	int ms_env;
} ms_ecall_init_kms_t;

typedef struct ms_ecall_remove_t {
	int ms_retval;
} ms_ecall_remove_t;

typedef struct ms_ecall_signin_t {
	int ms_retval;
} ms_ecall_signin_t;

typedef struct ms_ecall_signout_t {
	int ms_retval;
} ms_ecall_signout_t;

typedef struct ms_ecall_signup_t {
	int ms_retval;
} ms_ecall_signup_t;

typedef struct ms_ecall_get_role_t {
	char* ms_role;
	size_t ms_len;
} ms_ecall_get_role_t;

typedef struct ms_wc_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_test_t;

typedef struct ms_wc_benchmark_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_benchmark_test_t;

typedef struct ms_enc_wolfSSL_Init_t {
	int ms_retval;
} ms_enc_wolfSSL_Init_t;

typedef struct ms_enc_wolfTLSv1_2_client_method_t {
	long int ms_retval;
} ms_enc_wolfTLSv1_2_client_method_t;

typedef struct ms_enc_wolfTLSv1_2_server_method_t {
	long int ms_retval;
} ms_enc_wolfTLSv1_2_server_method_t;

typedef struct ms_enc_wolfSSL_CTX_new_t {
	long int ms_retval;
	long int ms_method;
} ms_enc_wolfSSL_CTX_new_t;

typedef struct ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
	int ms_is_server;
} ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_load_verify_buffer_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
	int ms_is_server;
} ms_enc_wolfSSL_CTX_load_verify_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
	int ms_is_server;
} ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_buffer_t {
	int ms_retval;
	long int ms_ctxId;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
	int ms_is_server;
} ms_enc_wolfSSL_CTX_use_certificate_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_set_cipher_list_t {
	int ms_retval;
	long int ms_ctxId;
	const char* ms_list;
	size_t ms_list_len;
} ms_enc_wolfSSL_CTX_set_cipher_list_t;

typedef struct ms_enc_wolfSSL_set_verify_client_t {
	int ms_retval;
	long int ms_ctxId;
} ms_enc_wolfSSL_set_verify_client_t;

typedef struct ms_enc_wolfSSL_set_verify_none_t {
	int ms_retval;
	long int ms_ctxId;
} ms_enc_wolfSSL_set_verify_none_t;

typedef struct ms_enc_wolfSSL_new_t {
	long int ms_retval;
	long int ms_ctxId;
} ms_enc_wolfSSL_new_t;

typedef struct ms_enc_wolfSSL_set_fd_t {
	int ms_retval;
	long int ms_sslId;
	int ms_fd;
} ms_enc_wolfSSL_set_fd_t;

typedef struct ms_enc_wolfSSL_accept_t {
	int ms_retval;
	long int ms_sslId;
} ms_enc_wolfSSL_accept_t;

typedef struct ms_enc_wolfSSL_connect_t {
	int ms_retval;
	long int ms_sslId;
} ms_enc_wolfSSL_connect_t;

typedef struct ms_enc_wolfSSL_write_t {
	int ms_retval;
	long int ms_sslId;
	const void* ms_in;
	int ms_sz;
} ms_enc_wolfSSL_write_t;

typedef struct ms_enc_wolfSSL_read_t {
	int ms_retval;
	long int ms_sslId;
	char* ms_out;
	int ms_sz;
} ms_enc_wolfSSL_read_t;

typedef struct ms_enc_wolfSSL_get_error_t {
	int ms_retval;
	long int ms_sslId;
	int ms_ret;
} ms_enc_wolfSSL_get_error_t;

typedef struct ms_enc_wolfSSL_free_t {
	long int ms_sslId;
} ms_enc_wolfSSL_free_t;

typedef struct ms_enc_wolfSSL_CTX_free_t {
	long int ms_ctxId;
} ms_enc_wolfSSL_CTX_free_t;

typedef struct ms_enc_wolfSSL_Cleanup_t {
	int ms_retval;
} ms_enc_wolfSSL_Cleanup_t;

typedef struct ms_enc_wolfSSL_CTX_UseSupportedCurve_t {
	int ms_retval;
	long int ms_ctxId;
} ms_enc_wolfSSL_CTX_UseSupportedCurve_t;

typedef struct ms_enc_wolfSSL_set_SNI_t {
	int ms_retval;
	long int ms_ctxId;
	const char* ms_buf;
	size_t ms_buf_len;
} ms_enc_wolfSSL_set_SNI_t;

typedef struct ms_enc_wolfSSL_secure_http_read_t {
	int ms_retval;
	long int ms_sslId;
	char* ms_out;
	int ms_sz;
} ms_enc_wolfSSL_secure_http_read_t;

typedef struct ms_enc_wolfSSL_secure_http_write_t {
	int ms_retval;
	long int ms_sslId;
	const char* ms_in;
	size_t ms_in_len;
} ms_enc_wolfSSL_secure_http_write_t;

typedef struct ms_ocall_ftell_t {
	unsigned int ms_retval;
	const char* ms_filename;
} ms_ocall_ftell_t;

typedef struct ms_ocall_fread_t {
	const char* ms_filename;
	char* ms_buf;
	unsigned int ms_size;
} ms_ocall_fread_t;

typedef struct ms_ocall_fremove_t {
	const char* ms_filename;
} ms_ocall_fremove_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxprotectedfs_exclusive_file_open_t {
	void* ms_retval;
	const char* ms_filename;
	uint8_t ms_read_only;
	int64_t* ms_file_size;
	int32_t* ms_error_code;
} ms_u_sgxprotectedfs_exclusive_file_open_t;

typedef struct ms_u_sgxprotectedfs_check_if_file_exists_t {
	uint8_t ms_retval;
	const char* ms_filename;
} ms_u_sgxprotectedfs_check_if_file_exists_t;

typedef struct ms_u_sgxprotectedfs_fread_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fread_node_t;

typedef struct ms_u_sgxprotectedfs_fwrite_node_t {
	int32_t ms_retval;
	void* ms_f;
	uint64_t ms_node_number;
	uint8_t* ms_buffer;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_fwrite_node_t;

typedef struct ms_u_sgxprotectedfs_fclose_t {
	int32_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fclose_t;

typedef struct ms_u_sgxprotectedfs_fflush_t {
	uint8_t ms_retval;
	void* ms_f;
} ms_u_sgxprotectedfs_fflush_t;

typedef struct ms_u_sgxprotectedfs_remove_t {
	int32_t ms_retval;
	const char* ms_filename;
} ms_u_sgxprotectedfs_remove_t;

typedef struct ms_u_sgxprotectedfs_recovery_file_open_t {
	void* ms_retval;
	const char* ms_filename;
} ms_u_sgxprotectedfs_recovery_file_open_t;

typedef struct ms_u_sgxprotectedfs_fwrite_recovery_node_t {
	uint8_t ms_retval;
	void* ms_f;
	uint8_t* ms_data;
	uint32_t ms_data_length;
} ms_u_sgxprotectedfs_fwrite_recovery_node_t;

typedef struct ms_u_sgxprotectedfs_do_file_recovery_t {
	int32_t ms_retval;
	const char* ms_filename;
	const char* ms_recovery_filename;
	uint32_t ms_node_size;
} ms_u_sgxprotectedfs_do_file_recovery_t;

typedef struct ms_ocall_current_time_t {
	double* ms_time;
} ms_ocall_current_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

static sgx_status_t SGX_CDECL sgx_ecall_init_kms(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_kms_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_kms_t* ms = SGX_CAST(ms_ecall_init_kms_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_init_kms(ms->ms_env);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_remove(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_remove_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_remove_t* ms = SGX_CAST(ms_ecall_remove_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_remove();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_signin(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_signin_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_signin_t* ms = SGX_CAST(ms_ecall_signin_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_signin();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_signout(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_signout_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_signout_t* ms = SGX_CAST(ms_ecall_signout_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_signout();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_signup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_signup_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_signup_t* ms = SGX_CAST(ms_ecall_signup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_signup();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_role(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_role_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_role_t* ms = SGX_CAST(ms_ecall_get_role_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_role = ms->ms_role;
	size_t _tmp_len = ms->ms_len;
	size_t _len_role = _tmp_len;
	char* _in_role = NULL;

	CHECK_UNIQUE_POINTER(_tmp_role, _len_role);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_role != NULL && _len_role != 0) {
		if ( _len_role % sizeof(*_tmp_role) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_role = (char*)malloc(_len_role)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_role, 0, _len_role);
	}

	ecall_get_role(_in_role, _tmp_len);
	if (_in_role) {
		if (memcpy_s(_tmp_role, _len_role, _in_role, _len_role)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_role) free(_in_role);
	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_test_t* ms = SGX_CAST(ms_wc_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_benchmark_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_benchmark_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_benchmark_test_t* ms = SGX_CAST(ms_wc_benchmark_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_benchmark_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Init_t* ms = SGX_CAST(ms_enc_wolfSSL_Init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Init();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_ON(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_ON();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_OFF(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_OFF();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_client_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_client_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_client_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_client_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_client_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_server_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_server_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_server_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_server_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_server_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_new_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_CTX_new(ms->ms_method);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_PrivateKey_buffer(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type, ms->ms_is_server);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_load_verify_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_load_verify_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_load_verify_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_load_verify_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_load_verify_buffer(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type, ms->ms_is_server);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_chain_buffer_format(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type, ms->ms_is_server);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_buffer(ms->ms_ctxId, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type, ms->ms_is_server);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_set_cipher_list(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_set_cipher_list_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_set_cipher_list_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_set_cipher_list_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_list = ms->ms_list;
	size_t _len_list = ms->ms_list_len ;
	char* _in_list = NULL;

	CHECK_UNIQUE_POINTER(_tmp_list, _len_list);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_list != NULL && _len_list != 0) {
		_in_list = (char*)malloc(_len_list);
		if (_in_list == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_list, _len_list, _tmp_list, _len_list)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_list[_len_list - 1] = '\0';
		if (_len_list != strlen(_in_list) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enc_wolfSSL_CTX_set_cipher_list(ms->ms_ctxId, (const char*)_in_list);

err:
	if (_in_list) free(_in_list);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_verify_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_verify_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_verify_client_t* ms = SGX_CAST(ms_enc_wolfSSL_set_verify_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_set_verify_client(ms->ms_ctxId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_verify_none(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_verify_none_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_verify_none_t* ms = SGX_CAST(ms_enc_wolfSSL_set_verify_none_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_set_verify_none(ms->ms_ctxId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_new_t* ms = SGX_CAST(ms_enc_wolfSSL_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_new(ms->ms_ctxId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_fd(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_fd_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_fd_t* ms = SGX_CAST(ms_enc_wolfSSL_set_fd_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_set_fd(ms->ms_sslId, ms->ms_fd);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_accept(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_accept_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_accept_t* ms = SGX_CAST(ms_enc_wolfSSL_accept_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_accept(ms->ms_sslId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_connect(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_connect_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_connect_t* ms = SGX_CAST(ms_enc_wolfSSL_connect_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_connect(ms->ms_sslId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_write(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_write_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_write_t* ms = SGX_CAST(ms_enc_wolfSSL_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const void* _tmp_in = ms->ms_in;
	int _tmp_sz = ms->ms_sz;
	size_t _len_in = _tmp_sz;
	void* _in_in = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in != NULL && _len_in != 0) {
		_in_in = (void*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in, _len_in, _tmp_in, _len_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_write(ms->ms_sslId, (const void*)_in_in, _tmp_sz);

err:
	if (_in_in) free(_in_in);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_read(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_read_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_read_t* ms = SGX_CAST(ms_enc_wolfSSL_read_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_out = ms->ms_out;
	int _tmp_sz = ms->ms_sz;
	size_t _len_out = _tmp_sz;
	char* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (char*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}

	ms->ms_retval = enc_wolfSSL_read(ms->ms_sslId, _in_out, _tmp_sz);
	if (_in_out) {
		if (memcpy_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_get_error(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_get_error_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_get_error_t* ms = SGX_CAST(ms_enc_wolfSSL_get_error_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_get_error(ms->ms_sslId, ms->ms_ret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_free_t* ms = SGX_CAST(ms_enc_wolfSSL_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	enc_wolfSSL_free(ms->ms_sslId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_free_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	enc_wolfSSL_CTX_free(ms->ms_ctxId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Cleanup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Cleanup_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Cleanup_t* ms = SGX_CAST(ms_enc_wolfSSL_Cleanup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Cleanup();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_UseSupportedCurve(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_UseSupportedCurve_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_UseSupportedCurve_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_UseSupportedCurve_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_CTX_UseSupportedCurve(ms->ms_ctxId);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_SNI(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_SNI_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_SNI_t* ms = SGX_CAST(ms_enc_wolfSSL_set_SNI_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_buf = ms->ms_buf;
	size_t _len_buf = ms->ms_buf_len ;
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_buf[_len_buf - 1] = '\0';
		if (_len_buf != strlen(_in_buf) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enc_wolfSSL_set_SNI(ms->ms_ctxId, (const char*)_in_buf);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_secure_http_read(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_secure_http_read_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_secure_http_read_t* ms = SGX_CAST(ms_enc_wolfSSL_secure_http_read_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_out = ms->ms_out;
	int _tmp_sz = ms->ms_sz;
	size_t _len_out = _tmp_sz;
	char* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out != NULL && _len_out != 0) {
		if ( _len_out % sizeof(*_tmp_out) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out = (char*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}

	ms->ms_retval = enc_wolfSSL_secure_http_read(ms->ms_sslId, _in_out, _tmp_sz);
	if (_in_out) {
		if (memcpy_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_secure_http_write(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_secure_http_write_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_secure_http_write_t* ms = SGX_CAST(ms_enc_wolfSSL_secure_http_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_in = ms->ms_in;
	size_t _len_in = ms->ms_in_len ;
	char* _in_in = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in != NULL && _len_in != 0) {
		_in_in = (char*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in, _len_in, _tmp_in, _len_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_in[_len_in - 1] = '\0';
		if (_len_in != strlen(_in_in) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enc_wolfSSL_secure_http_write(ms->ms_sslId, (const char*)_in_in);

err:
	if (_in_in) free(_in_in);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[35];
} g_ecall_table = {
	35,
	{
		{(void*)(uintptr_t)sgx_ecall_init_kms, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_remove, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_signin, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_signout, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_signup, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_role, 0, 0},
		{(void*)(uintptr_t)sgx_wc_test, 0, 0},
		{(void*)(uintptr_t)sgx_wc_benchmark_test, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Init, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_ON, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_OFF, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_client_method, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_server_method, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_new, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_load_verify_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_set_cipher_list, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_verify_client, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_verify_none, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_new, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_fd, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_accept, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_connect, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_write, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_read, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_get_error, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_free, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_free, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Cleanup, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_UseSupportedCurve, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_SNI, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_secure_http_read, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_secure_http_write, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[23][35];
} g_dyn_entry_table = {
	23,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_ftell(unsigned int* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_ocall_ftell_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftell_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftell_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftell_t));
	ocalloc_size -= sizeof(ms_ocall_ftell_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fread(const char* filename, char* buf, unsigned int size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_buf = size;

	ms_ocall_fread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fread_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fread_t));
	ocalloc_size -= sizeof(ms_ocall_fread_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (char*)__tmp;
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fremove(const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_ocall_fremove_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fremove_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fremove_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fremove_t));
	ocalloc_size -= sizeof(ms_ocall_fremove_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(void** retval, const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_file_size = sizeof(int64_t);
	size_t _len_error_code = sizeof(int32_t);

	ms_u_sgxprotectedfs_exclusive_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t);
	void *__tmp = NULL;

	void *__tmp_file_size = NULL;
	void *__tmp_error_code = NULL;

	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(file_size, _len_file_size);
	CHECK_ENCLAVE_POINTER(error_code, _len_error_code);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_size != NULL) ? _len_file_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (error_code != NULL) ? _len_error_code : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_exclusive_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_exclusive_file_open_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	ms->ms_read_only = read_only;
	if (file_size != NULL) {
		ms->ms_file_size = (int64_t*)__tmp;
		__tmp_file_size = __tmp;
		if (_len_file_size % sizeof(*file_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_file_size, 0, _len_file_size);
		__tmp = (void *)((size_t)__tmp + _len_file_size);
		ocalloc_size -= _len_file_size;
	} else {
		ms->ms_file_size = NULL;
	}
	
	if (error_code != NULL) {
		ms->ms_error_code = (int32_t*)__tmp;
		__tmp_error_code = __tmp;
		if (_len_error_code % sizeof(*error_code) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_error_code, 0, _len_error_code);
		__tmp = (void *)((size_t)__tmp + _len_error_code);
		ocalloc_size -= _len_error_code;
	} else {
		ms->ms_error_code = NULL;
	}
	
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (file_size) {
			if (memcpy_s((void*)file_size, _len_file_size, __tmp_file_size, _len_file_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (error_code) {
			if (memcpy_s((void*)error_code, _len_error_code, __tmp_error_code, _len_error_code)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_check_if_file_exists_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_check_if_file_exists_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_check_if_file_exists_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fread_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fread_node_t);
	void *__tmp = NULL;

	void *__tmp_buffer = NULL;

	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fread_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fread_node_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fread_node_t);

	ms->ms_f = f;
	ms->ms_node_number = node_number;
	if (buffer != NULL) {
		ms->ms_buffer = (uint8_t*)__tmp;
		__tmp_buffer = __tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buffer, 0, _len_buffer);
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buffer) {
			if (memcpy_s((void*)buffer, _len_buffer, __tmp_buffer, _len_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(int32_t* retval, void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = node_size;

	ms_u_sgxprotectedfs_fwrite_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_node_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buffer, _len_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buffer != NULL) ? _len_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_node_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fwrite_node_t);

	ms->ms_f = f;
	ms->ms_node_number = node_number;
	if (buffer != NULL) {
		ms->ms_buffer = (uint8_t*)__tmp;
		if (_len_buffer % sizeof(*buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buffer, _len_buffer)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		ocalloc_size -= _len_buffer;
	} else {
		ms->ms_buffer = NULL;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int32_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fclose_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fclose_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fclose_t);

	ms->ms_f = f;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxprotectedfs_fflush_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fflush_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fflush_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fflush_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fflush_t);

	ms->ms_f = f;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_remove(int32_t* retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_remove_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_remove_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_remove_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_remove_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_remove_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;

	ms_u_sgxprotectedfs_recovery_file_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_recovery_file_open_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_recovery_file_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_recovery_file_open_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_recovery_file_open_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(uint8_t* retval, void* f, uint8_t* data, uint32_t data_length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = data_length * sizeof(uint8_t);

	ms_u_sgxprotectedfs_fwrite_recovery_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(data, _len_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data != NULL) ? _len_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_fwrite_recovery_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_fwrite_recovery_node_t);

	ms->ms_f = f;
	if (data != NULL) {
		ms->ms_data = (uint8_t*)__tmp;
		if (_len_data % sizeof(*data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, data, _len_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_data);
		ocalloc_size -= _len_data;
	} else {
		ms->ms_data = NULL;
	}
	
	ms->ms_data_length = data_length;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(int32_t* retval, const char* filename, const char* recovery_filename, uint32_t node_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_recovery_filename = recovery_filename ? strlen(recovery_filename) + 1 : 0;

	ms_u_sgxprotectedfs_do_file_recovery_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxprotectedfs_do_file_recovery_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(recovery_filename, _len_recovery_filename);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (recovery_filename != NULL) ? _len_recovery_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxprotectedfs_do_file_recovery_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxprotectedfs_do_file_recovery_t));
	ocalloc_size -= sizeof(ms_u_sgxprotectedfs_do_file_recovery_t);

	if (filename != NULL) {
		ms->ms_filename = (const char*)__tmp;
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}
	
	if (recovery_filename != NULL) {
		ms->ms_recovery_filename = (const char*)__tmp;
		if (_len_recovery_filename % sizeof(*recovery_filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, recovery_filename, _len_recovery_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_recovery_filename);
		ocalloc_size -= _len_recovery_filename;
	} else {
		ms->ms_recovery_filename = NULL;
	}
	
	ms->ms_node_size = node_size;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_current_time(double* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(double);

	ms_ocall_current_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_current_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;

	CHECK_ENCLAVE_POINTER(time, _len_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (time != NULL) ? _len_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_current_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_current_time_t));
	ocalloc_size -= sizeof(ms_ocall_current_time_t);

	if (time != NULL) {
		ms->ms_time = (double*)__tmp;
		__tmp_time = __tmp;
		if (_len_time % sizeof(*time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
		ocalloc_size -= _len_time;
	} else {
		ms->ms_time = NULL;
	}
	
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (time) {
			if (memcpy_s((void*)time, _len_time, __tmp_time, _len_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_low_res_time(int* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(int);

	ms_ocall_low_res_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_low_res_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;

	CHECK_ENCLAVE_POINTER(time, _len_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (time != NULL) ? _len_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_low_res_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_low_res_time_t));
	ocalloc_size -= sizeof(ms_ocall_low_res_time_t);

	if (time != NULL) {
		ms->ms_time = (int*)__tmp;
		__tmp_time = __tmp;
		if (_len_time % sizeof(*time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
		ocalloc_size -= _len_time;
	} else {
		ms->ms_time = NULL;
	}
	
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (time) {
			if (memcpy_s((void*)time, _len_time, __tmp_time, _len_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recv_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recv_t));
	ocalloc_size -= sizeof(ms_ocall_recv_t);

	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_t));
	ocalloc_size -= sizeof(ms_ocall_send_t);

	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

