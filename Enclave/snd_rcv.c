
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "Enclave_t.h"
#include "sgx_trts.h"
#include <string.h>
#include <stdio.h>
#include <sgx_thread.h>



size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    int sgxStatus;
    sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}