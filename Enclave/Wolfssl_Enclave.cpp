#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>
#include "Enclave.h"

#include "Enclave_t.h"
#include "sgx_trts.h"
#include <sgx_thread.h>
#include <vector>
#include "HttpHandler.hpp"
#include "Types.h"
#include "UsersStorage.hpp"
#include "CertKeyStorage.hpp"

#include "jsonsgx.hpp"

using json = nlohmann::json;

extern CertKeyStorage ks_certs;


#if defined(XMALLOC_USER) || defined(XMALLOC_OVERRIDE)
    #warning verfication of heap hint pointers needed when overriding default malloc/free
#endif

/* Max number of WOLFSSL_CTX's */
#ifndef MAX_WOLFSSL_CTX
#define MAX_WOLFSSL_CTX 300
#endif
WOLFSSL_CTX* CTX_TABLE[MAX_WOLFSSL_CTX];

/* Max number of WOLFSSL's */
#ifndef MAX_WOLFSSL
#define MAX_WOLFSSL 300
#endif
WOLFSSL* SSL_TABLE[MAX_WOLFSSL];

extern UsersStorage ks_ukeys;

/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
static long AddCTX(WOLFSSL_CTX* ctx)
{
    long i;
    for (i = 0; i < MAX_WOLFSSL_CTX; i++) {
         if (CTX_TABLE[i] == NULL) {
             CTX_TABLE[i] = ctx;
             return i;
         }
    }
    return -1;
}


/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
static long AddSSL(WOLFSSL* ssl)
{
    long i;
    for (i = 0; i < MAX_WOLFSSL; i++) {
         if (SSL_TABLE[i] == NULL) {
             SSL_TABLE[i] = ssl;
             return i;
         }
    }
    return -1;
}


/* returns the WOLFSSL_CTX pointer on success and NULL on failure */
static WOLFSSL_CTX* GetCTX(long id)
{
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return NULL;
    return CTX_TABLE[id];
}


/* returns the WOLFSSL pointer on success and NULL on failure */
static WOLFSSL* GetSSL(long id)
{
    if (id >= MAX_WOLFSSL || id < 0)
        return NULL;
    return SSL_TABLE[id];
}


/* Free's and removes the WOLFSSL_CTX associated with 'id' */
static void RemoveCTX(long id)
{
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return;
    wolfSSL_CTX_free(CTX_TABLE[id]);
    CTX_TABLE[id] = NULL;
}


/* Free's and removes the WOLFSSL associated with 'id' */
static void RemoveSSL(long id)
{
    if (id >= MAX_WOLFSSL || id < 0)
        return;
    wolfSSL_free(SSL_TABLE[id]);
    SSL_TABLE[id] = NULL;
}

#if defined(WOLFSSL_STATIC_MEMORY)
/* check on heap hint when used, aborts if pointer is not in Enclave.
 * In the default case where wolfSSL_Malloc is used the heap hint pointer is not
 * used.*/
static void checkHeapHint(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    WOLFSSL_HEAP_HINT* heap;
    if ((heap = (WOLFSSL_HEAP_HINT*)wolfSSL_CTX_GetHeap(ctx, ssl)) != NULL) {
        if(sgx_is_within_enclave(heap, sizeof(WOLFSSL_HEAP_HINT)) != 1)
            abort();
        if(sgx_is_within_enclave(heap->memory, sizeof(WOLFSSL_HEAP)) != 1)
            abort();
    }
}
#endif /* WOLFSSL_STATIC_MEMORY */


int wc_test(void* args)
{
#ifdef HAVE_WOLFSSL_TEST
	return wolfcrypt_test(args);
#else
    /* wolfSSL test not compiled in! */
    return -1;
#endif /* HAVE_WOLFSSL_TEST */
}

int wc_benchmark_test(void* args)
{

#ifdef HAVE_WOLFSSL_BENCHMARK
    return benchmark_test(args);
#else
    /* wolfSSL benchmark not compiled in! */
    return -1;
#endif /* HAVE_WOLFSSL_BENCHMARK */
}

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void)
{
    wolfSSL_Debugging_OFF();
}

int enc_wolfSSL_Init(void)
{
    return wolfSSL_Init();
}


#define WOLFTLSv12_CLIENT 1
#define WOLFTLSv12_SERVER 2

long enc_wolfTLSv1_2_client_method(void)
{
    return WOLFTLSv12_CLIENT;
}

long enc_wolfTLSv1_2_server_method(void)
{
    return WOLFTLSv12_SERVER;
}


/* returns method releated to id */
static WOLFSSL_METHOD* GetMethod(long id)
{
    switch (id) {
        case WOLFTLSv12_CLIENT: return wolfTLSv1_2_client_method();
        case WOLFTLSv12_SERVER: return wolfTLSv1_2_server_method();
        default:
            return NULL;
    }
}


long enc_wolfSSL_CTX_new(long method)
{
    WOLFSSL_CTX* ctx;
    long id = -1;

    ctx = wolfSSL_CTX_new(GetMethod(method));
    if (ctx != NULL) {
        id = AddCTX(ctx);
    }
    return id;
}



int enc_wolfSSL_CTX_set_cipher_list(long id, const char* list)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    return wolfSSL_CTX_set_cipher_list(ctx, list);
}



int enc_wolfSSL_set_verify_client(long id){
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, 0);
    return 1;
}


int enc_wolfSSL_set_verify_none(long id){
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);
    return 1;
}

long enc_wolfSSL_new(long id)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    long ret = -1;

    ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }    
    ssl = wolfSSL_new(ctx);
    if (ssl != NULL) {
        ret = AddSSL(ssl);
    }
    return ret;
}

int enc_wolfSSL_set_fd(long sslId, int fd)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_set_fd(ssl, fd);
}

int enc_wolfSSL_connect(long sslId)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_connect(ssl);
}

int enc_wolfSSL_accept(long sslId)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_accept(ssl);
}


int enc_wolfSSL_set_SNI(long id, const char *hostname)
{
    WOLFSSL_CTX *ctx;
    ctx = GetCTX(id);
    if (ctx == NULL)
    {
        return -1;
    }

    return wolfSSL_CTX_UseSNI(ctx, 0, hostname, XSTRLEN(hostname));
}

int json_parse=0;
char json_message[65536];
int enc_wolfSSL_secure_http_read(long sslId,char *data, int sz)
{
    WOLFSSL *ssl = GetSSL(sslId);
    if (ssl == NULL)
    {
        return -1;
    }
    int retval;
    char rcvBuff[65536] = "";
    retval = wolfSSL_read(ssl, rcvBuff, sz);
    if((rcvBuff[0]=='{' || rcvBuff[0]=='[') && strlen(rcvBuff)>10){
        handle_http_read(rcvBuff);
    }
    int i;
    for(i=0;i<strlen(rcvBuff);i++){
        data[i]=rcvBuff[i];
    }
    return retval;
}

int enc_wolfSSL_secure_http_write(long sslId, const char *data)
{
    WOLFSSL *ssl = GetSSL(sslId);
    if (ssl == NULL)
    {
        return -1;
    }

    return wolfSSL_write(ssl, data, strlen(data));
}

int enc_wolfSSL_CTX_UseSupportedCurve(long id)
{
    WOLFSSL_CTX *ctx = GetCTX(id);
    if (ctx == NULL)
    {
        return -1;
    }
    return wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
}


int enc_wolfSSL_write(long sslId, const void * in, int sz)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_write(ssl, in, sz);
}

int enc_wolfSSL_read(long sslId, char *data, int sz)
{
    WOLFSSL *ssl = GetSSL(sslId);
    if (ssl == NULL)
    {
        return -1;
    }
    return wolfSSL_read(ssl, data, sz);
}




int enc_wolfSSL_get_error(long sslId, int ret)
{
    WOLFSSL* ssl = GetSSL(sslId);
    if (ssl == NULL) {
        return -1;
    }
    return wolfSSL_get_error(ssl, ret);
}

void enc_wolfSSL_free(long sslId)
{
    RemoveSSL(sslId);
}

void enc_wolfSSL_CTX_free(long id)
{
    RemoveCTX(id);
}


int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(long id,
        const unsigned char* buf, long sz, int type, int is_https_server)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }

    if(is_https_server==1) {
        return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx,  (unsigned char *) ks_certs.GetChain().c_str(), ks_certs.GetChain().length(), type);
    }else{
        return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz, type);
    }
}

int enc_wolfSSL_CTX_use_certificate_buffer(long id,
        const unsigned char* buf, long sz, int type, int is_https_server)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1;
    }
    
    if(is_https_server==1) {
        return wolfSSL_CTX_use_certificate_buffer(ctx,  (unsigned char *) ks_certs.GetServerCert().c_str(), ks_certs.GetServerCert().length(), type);
    }else{
        return wolfSSL_CTX_use_certificate_buffer(ctx, buf, sz, type);
    }
}


int enc_wolfSSL_CTX_use_PrivateKey_buffer(long id, const unsigned char* buf,
                                            long sz, int type, int is_https_server)
{
    WOLFSSL_CTX* ctx = GetCTX(id);
    if (ctx == NULL) {
        return -1; 
    }

    if(is_https_server==1) {
        static const int certBufSz = (int) sizeof(ks_certs.GetServerKey().c_str());

        return wolfSSL_CTX_use_PrivateKey_buffer(ctx,  (unsigned char *) ks_certs.GetServerKey().c_str(), ks_certs.GetServerKey().length(), type);
    }else{
        return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sz, type);
    }
}


int enc_wolfSSL_CTX_load_verify_buffer(long id, const unsigned char *in,
                                       long sz, int format, int is_https_server)
{
    WOLFSSL_CTX *ctx = GetCTX(id);
    if (ctx == NULL)
    {
        return -1; 
    }
    if(is_https_server==1) {
         return wolfSSL_CTX_load_verify_buffer(ctx, (unsigned char *)ks_certs.GetCA().c_str(), ks_certs.GetCA().length(), format);
    }else{
        return wolfSSL_CTX_load_verify_buffer(ctx, in, sz, format);
    }
}

int enc_wolfSSL_Cleanup(void)
{
    long id;

    /* free up all WOLFSSL's */
    for (id = 0; id < MAX_WOLFSSL; id++)
        RemoveSSL(id);

    /* free up all WOLFSSL_CTX's */
    for (id = 0; id < MAX_WOLFSSL_CTX; id++)
        RemoveCTX(id);
    wolfSSL_Cleanup();
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}
