
#!/bin/bash

# Note OPENSSL_EXTRA is incompatible with WOLFSSL_SGX

CFLAGS_NEW=""
CFLAGS_NEW="${CFLAGS_NEW} -DWOLFSSL_AES_DIRECT -DHAVE_AES_KEYWRAP" # Needed for AES-KeyWrap, used in key hierarchy
CFLAGS_NEW="${CFLAGS_NEW} -DHAVE_ECC" # Needed to support ECC curves larger than 256-bits
CFLAGS_NEW="${CFLAGS_NEW} -DWOLFSSL_STATIC_RSA -DHAVE_SUPPORTED_CURVES -DHAVE_SNI -DHAVE_TLS_EXTENSIONS" # Options for TLS support

if [[ -n "${ENV_DEBUG}" ]] ;
then CFLAGS_NEW="${CFLAGS_NEW}" # -DDEBUG_WOLFSSL" Disable this because I'm too lazy to implement printf() in the cscore enclave
fi

export CFLAGS="${CFLAGS} ${CFLAGS_NEW}"

make -f sgx_t_static.mk SGX_MODE="${ENV_SGX_MODE}" HAVE_WOLFSSL_BENCHMARK=0 HAVE_WOLFSSL_TEST=0 HAVE_WOLFSSL_SP=1 SGX_DEBUG="${ENV_DEBUG}"