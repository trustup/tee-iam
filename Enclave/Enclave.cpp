
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <map>
#include <map>
#include <vector>
#include <stdlib.h> /* srand, rand */

#include "UsersStorage.hpp"
#include "CertKeyStorage.hpp"
#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include "Wolfssl_Enclave.h"
#include "HttpHandler.hpp"
#include <sgx_trts.h>
// curl --insecure -v -d '{"uuid": "gmazzeo","op":
// "signup","email":"gmazzeo@cerict.it","role":"researcher","pwd":"superpippo"}'
// -H "Content-Type: application/json" -X POST
// https://localhost:8866/accesshandler/signup

#define DEBUG_MODE

using namespace std;

UsersStorage ks_ukeys;
CertKeyStorage ks_certs;
std::string json_message_rcvd;
std::string uuid;
std::string received_code;
std::vector<std::string> SIGNED_USERS;
std::map<std::string, std::string> ROLES;

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
#define DEBUG_MODE

void
xprintf(const char *fmt, ...)
{
    char buf[104888] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, 104888, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void
ecall_init_kms(int env)
{
    // ks_certs=CertKeyStorage(env);
    // ks_certs.LoadCerts();

    xprintf("[ENCLAVE] Initialization of Keys Completed!");
}

string
byte_2_str(const unsigned char *bytes, int size)
{
    string str;

    for (int i = 0; i < size; ++i) {
        int n = static_cast<int>(bytes[i]);
        str = str + to_string(n);
    }
    return str;
}

int
ecall_signup()
{
    using json = nlohmann::json;
    try {
        json jdoc = json::parse(json_message_rcvd);
        if (!jdoc.contains("role") || !jdoc.contains("op")
            || !jdoc.contains("uuid") || !jdoc.contains("pwd")
            || !jdoc.contains("username") || !jdoc.contains("email"))
            return -5;
    } catch (...) {
        xprintf("Error in parsing the user entry from the storage system");
        return -5;
    }

    return ks_ukeys.append(uuid, json_message_rcvd);
}

std::string role;
std::string authcode;
int
ecall_signin()
{

    if (!ks_ukeys.exist(uuid)) {
        return -1;
    }
    else {
        auto it = std::find(SIGNED_USERS.begin(), SIGNED_USERS.end(), uuid);
        if (it != SIGNED_USERS.end()) {
            return -2;
        }
        else {
            role = ks_ukeys.getRole(uuid);
            if (role == "badparsing")
                return -5;

            std::string email = ks_ukeys.getEmail(uuid);
            if (role == "badparsing")
                return -5;
            std::string const legalChars("0123456789");
            while (authcode.size() != 6) {
                unsigned int r;
                sgx_read_rand((unsigned char *)&r, sizeof(unsigned int));
                r = r % 9;
                authcode += legalChars[r];
            }
            ocall_send_email(email.c_str(), authcode.c_str());
            return 2;
        }
    }
}

int
ecall_2fa()
{
    if (received_code != authcode) {
        return -1;
    }

    SIGNED_USERS.push_back(uuid);
    return 1;
}

void
ecall_get_role(char *r, size_t len)
{
    for (size_t i = 0; i < role.size(); i++) {
        r[i] = role[i];
    }
    role = "";
}

int
ecall_remove()
{
    return ks_ukeys.remove(uuid);
}

int
ecall_signout()
{
    // std::string users=ks_apikeys.getUsers();
    // return users.size();
    auto it = std::find(SIGNED_USERS.begin(), SIGNED_USERS.end(), uuid);
    if (it == SIGNED_USERS.end()) {
        return -2;
    }
    else {
        auto itr = std::find(SIGNED_USERS.begin(), SIGNED_USERS.end(), uuid);
        if (itr != SIGNED_USERS.end())
            SIGNED_USERS.erase(itr);

        return 2;
    }
}
