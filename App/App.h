#ifndef APP_H
#define APP_H

#include <sys/types.h> /* for send/recv */
#include <sys/socket.h> /* for send/recv */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include <string>
#include <spdlog/spdlog.h>

#include "Enclave_u.h"   /* contains untrusted wrapper functions used to call enclave functions*/

#define BENCH_RSA
#define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */
extern spdlog::logger *logger;


using namespace std;

std::string getEnvVar(std::string const& key);

enum BenchmarkBounds {
	/* these numbers are lower then default wolfSSL one to collect benchmark values faster for GUI */
	numBlocks = 10, /* how many megs to test */
	ntimes = 30 /* how many itteration to run RSA decrypt/encrypt */
};

#endif
