#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_ftell(void* pms)
{
	ms_ocall_ftell_t* ms = SGX_CAST(ms_ocall_ftell_t*, pms);
	ms->ms_retval = ocall_ftell(ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fread(void* pms)
{
	ms_ocall_fread_t* ms = SGX_CAST(ms_ocall_fread_t*, pms);
	ocall_fread(ms->ms_filename, ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fremove(void* pms)
{
	ms_ocall_fremove_t* ms = SGX_CAST(ms_ocall_fremove_t*, pms);
	ocall_fremove(ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_exclusive_file_open(void* pms)
{
	ms_u_sgxprotectedfs_exclusive_file_open_t* ms = SGX_CAST(ms_u_sgxprotectedfs_exclusive_file_open_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_exclusive_file_open(ms->ms_filename, ms->ms_read_only, ms->ms_file_size, ms->ms_error_code);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_check_if_file_exists(void* pms)
{
	ms_u_sgxprotectedfs_check_if_file_exists_t* ms = SGX_CAST(ms_u_sgxprotectedfs_check_if_file_exists_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_check_if_file_exists(ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_fread_node(void* pms)
{
	ms_u_sgxprotectedfs_fread_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fread_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fread_node(ms->ms_f, ms->ms_node_number, ms->ms_buffer, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_fwrite_node(void* pms)
{
	ms_u_sgxprotectedfs_fwrite_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fwrite_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fwrite_node(ms->ms_f, ms->ms_node_number, ms->ms_buffer, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_fclose(void* pms)
{
	ms_u_sgxprotectedfs_fclose_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fclose_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fclose(ms->ms_f);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_fflush(void* pms)
{
	ms_u_sgxprotectedfs_fflush_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fflush_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fflush(ms->ms_f);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_remove(void* pms)
{
	ms_u_sgxprotectedfs_remove_t* ms = SGX_CAST(ms_u_sgxprotectedfs_remove_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_remove(ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_recovery_file_open(void* pms)
{
	ms_u_sgxprotectedfs_recovery_file_open_t* ms = SGX_CAST(ms_u_sgxprotectedfs_recovery_file_open_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_recovery_file_open(ms->ms_filename);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_fwrite_recovery_node(void* pms)
{
	ms_u_sgxprotectedfs_fwrite_recovery_node_t* ms = SGX_CAST(ms_u_sgxprotectedfs_fwrite_recovery_node_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_fwrite_recovery_node(ms->ms_f, ms->ms_data, ms->ms_data_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxprotectedfs_do_file_recovery(void* pms)
{
	ms_u_sgxprotectedfs_do_file_recovery_t* ms = SGX_CAST(ms_u_sgxprotectedfs_do_file_recovery_t*, pms);
	ms->ms_retval = u_sgxprotectedfs_do_file_recovery(ms->ms_filename, ms->ms_recovery_filename, ms->ms_node_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_current_time(void* pms)
{
	ms_ocall_current_time_t* ms = SGX_CAST(ms_ocall_current_time_t*, pms);
	ocall_current_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[23];
} ocall_table_Enclave = {
	23,
	{
		(void*)Enclave_ocall_ftell,
		(void*)Enclave_ocall_fread,
		(void*)Enclave_ocall_fremove,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_u_sgxprotectedfs_exclusive_file_open,
		(void*)Enclave_u_sgxprotectedfs_check_if_file_exists,
		(void*)Enclave_u_sgxprotectedfs_fread_node,
		(void*)Enclave_u_sgxprotectedfs_fwrite_node,
		(void*)Enclave_u_sgxprotectedfs_fclose,
		(void*)Enclave_u_sgxprotectedfs_fflush,
		(void*)Enclave_u_sgxprotectedfs_remove,
		(void*)Enclave_u_sgxprotectedfs_recovery_file_open,
		(void*)Enclave_u_sgxprotectedfs_fwrite_recovery_node,
		(void*)Enclave_u_sgxprotectedfs_do_file_recovery,
		(void*)Enclave_ocall_current_time,
		(void*)Enclave_ocall_low_res_time,
		(void*)Enclave_ocall_recv,
		(void*)Enclave_ocall_send,
	}
};
sgx_status_t ecall_init_kms(sgx_enclave_id_t eid, int env)
{
	sgx_status_t status;
	ms_ecall_init_kms_t ms;
	ms.ms_env = env;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_remove(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_remove_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_signin(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_signin_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_signout(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_signout_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_signup(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_signup_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_role(sgx_enclave_id_t eid, char* role, size_t len)
{
	sgx_status_t status;
	ms_ecall_get_role_t ms;
	ms.ms_role = role;
	ms.ms_len = len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_benchmark_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Init_t ms;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_OFF(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, long int* retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_client_method_t ms;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfTLSv1_2_server_method(sgx_enclave_id_t eid, long int* retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_server_method_t ms;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, long int* retval, long int method)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_new_t ms;
	ms.ms_method = method;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	ms.ms_is_server = is_server;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_load_verify_buffer_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	ms.ms_is_server = is_server;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	ms.ms_is_server = is_server;
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, long int ctxId, const unsigned char* buf, long int sz, int type, int is_server)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	ms.ms_is_server = is_server;
	status = sgx_ecall(eid, 17, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_set_cipher_list(sgx_enclave_id_t eid, int* retval, long int ctxId, const char* list)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_set_cipher_list_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_list = list;
	ms.ms_list_len = list ? strlen(list) + 1 : 0;
	status = sgx_ecall(eid, 18, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_verify_client(sgx_enclave_id_t eid, int* retval, long int ctxId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_verify_client_t ms;
	ms.ms_ctxId = ctxId;
	status = sgx_ecall(eid, 19, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_verify_none(sgx_enclave_id_t eid, int* retval, long int ctxId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_verify_none_t ms;
	ms.ms_ctxId = ctxId;
	status = sgx_ecall(eid, 20, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, long int* retval, long int ctxId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_new_t ms;
	ms.ms_ctxId = ctxId;
	status = sgx_ecall(eid, 21, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, long int sslId, int fd)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_fd_t ms;
	ms.ms_sslId = sslId;
	ms.ms_fd = fd;
	status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_accept(sgx_enclave_id_t eid, int* retval, long int sslId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_accept_t ms;
	ms.ms_sslId = sslId;
	status = sgx_ecall(eid, 23, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, long int sslId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_connect_t ms;
	ms.ms_sslId = sslId;
	status = sgx_ecall(eid, 24, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, long int sslId, const void* in, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_write_t ms;
	ms.ms_sslId = sslId;
	ms.ms_in = in;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 25, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, long int sslId, char* out, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_read_t ms;
	ms.ms_sslId = sslId;
	ms.ms_out = out;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 26, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, long int sslId, int ret)
{
	sgx_status_t status;
	ms_enc_wolfSSL_get_error_t ms;
	ms.ms_sslId = sslId;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 27, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, long int sslId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_free_t ms;
	ms.ms_sslId = sslId;
	status = sgx_ecall(eid, 28, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, long int ctxId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_free_t ms;
	ms.ms_ctxId = ctxId;
	status = sgx_ecall(eid, 29, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Cleanup_t ms;
	status = sgx_ecall(eid, 30, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_UseSupportedCurve(sgx_enclave_id_t eid, int* retval, long int ctxId)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_UseSupportedCurve_t ms;
	ms.ms_ctxId = ctxId;
	status = sgx_ecall(eid, 31, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_SNI(sgx_enclave_id_t eid, int* retval, long int ctxId, const char* buf)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_SNI_t ms;
	ms.ms_ctxId = ctxId;
	ms.ms_buf = buf;
	ms.ms_buf_len = buf ? strlen(buf) + 1 : 0;
	status = sgx_ecall(eid, 32, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_secure_http_read(sgx_enclave_id_t eid, int* retval, long int sslId, char* out, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_secure_http_read_t ms;
	ms.ms_sslId = sslId;
	ms.ms_out = out;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 33, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_secure_http_write(sgx_enclave_id_t eid, int* retval, long int sslId, const char* in)
{
	sgx_status_t status;
	ms_enc_wolfSSL_secure_http_write_t ms;
	ms.ms_sslId = sslId;
	ms.ms_in = in;
	ms.ms_in_len = in ? strlen(in) + 1 : 0;
	status = sgx_ecall(eid, 34, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

