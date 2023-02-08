#pragma once

#include "Enclave.h" /* ocalls */
#include <map>
#include <string>
#include <vector>
#include "sgx_tprotected_fs.h"
#include "jsonsgx.hpp"
#include "Types.h"
#include "Enclave_t.h" /* print_string */
#include <queue>

#define DEBUG_MODE

using json = nlohmann::json;

class UsersStorage
{
  private:
    std::map<std::string, std::string> USERSENTRIES;

  public:
    UsersStorage();
    UsersStorage(const char *filename);
    int append(std::string uuid, std::string key);
    int remove(std::string uuid);
    std::string getRole(std::string uuid);
    std::string getEmail(std::string uuid);
    bool exist(std::string uuid);
    std::string getAll();
};

inline UsersStorage::UsersStorage()
{
    std::string filename = "/SecureDBdata/users.keys";
    SGX_FILE *handler = sgx_fopen_auto_key(filename.c_str(), "r");
    if (handler == NULL) {
#ifdef DEBUG_MODE
        xprintf("[KEYSTORAGE - USERS] No file found - Creating a new one");
#endif
        sgx_fclose(sgx_fopen_auto_key(filename.c_str(), "w"));
    }
    else {
        sgx_fseek(handler, 0, SEEK_END);
        long c_fsize = sgx_ftell(handler) + 1;
        sgx_fseek(handler, 0, SEEK_SET);

        char *data_buff = (char *)malloc(c_fsize + 1);
        sgx_fread(data_buff, c_fsize, 1, handler);

        if (sgx_fclose(handler) == 0) {
#ifdef DEBUG_MODE
            xprintf("[ENCLAVE] Encrypted File Successfully Closed during Load");
#endif
        }
        else {
            xprintf("Error while closing file...");
        }

        try {
            auto j = json::parse(data_buff);
            for (auto &curr_obj : j) {

                std::string uuid = curr_obj["uuid"].get<std::string>();
                USERSENTRIES[uuid] = curr_obj["key_data"].get<std::string>();

#ifdef DEBUG_MODE
                xprintf("[KEYSTORAGE - USERS] Loading:  %s - %s", uuid.c_str(),
                        curr_obj["key_data"].get<std::string>().c_str());
#else
                xprintf("[KEYSTORAGE - USERS] Loading:  %s ", uuid.c_str());
#endif
            }
        } catch (...) {
#ifdef DEBUG_MODE
            xprintf("[KEYSTORAGE - USERS] ERROR while parsing");
#endif
        }

        free(data_buff);
    }
}

inline int
UsersStorage::append(std::string uuid, std::string key)
{
    std::string filename = "/SecureDBdata/users.keys";

    try {

        auto it = USERSENTRIES.find(uuid);
        if (it != USERSENTRIES.end()) {
            xprintf("[KEYSTORAGE - USERS] ERROR The user key %s already exists "
                    "- Cannot add the key",
                    uuid.c_str());
            return -2;
        }

        SGX_FILE *handler = sgx_fopen_auto_key(filename.c_str(), "r");
        if (handler == NULL) {
#ifdef DEBUG_MODE
            xprintf("[KEYSTORAGE - USERS] ERROR Opening Encrypted File during "
                    "Load");
#endif
            sgx_fclose(sgx_fopen_auto_key(filename.c_str(), "w"));
            return -1;
        }

        sgx_fseek(handler, 0, SEEK_END);
        long c_fsize = sgx_ftell(handler) + 1;
        sgx_fseek(handler, 0, SEEK_SET);

        char *data;
        json storage_doc;
        if (c_fsize > 1) {
            data = (char *)malloc(c_fsize + 1);
            sgx_fread(data, c_fsize, 1, handler);
            sgx_fclose(handler);
            try {
                storage_doc = json::parse(data);
            } catch (...) {
                xprintf("Error while parsing storage doc");
                return -1;
            }
        }
        else {
            storage_doc = json::array();
        }

        USERSENTRIES[uuid] = key;

        json new_j_entry;
        new_j_entry["uuid"] = uuid;
        new_j_entry["key_data"] = key;
        storage_doc.push_back(new_j_entry);

        handler = sgx_fopen_auto_key(filename.c_str(), "w");
        sgx_fwrite(storage_doc.dump().c_str(), storage_doc.dump().size() + 1, 1,
                   handler);
        sgx_fflush(handler);

        xprintf("[KEYSTORAGE - USERS] Key for user %s appended!", uuid.c_str());

        if (sgx_fclose(handler) == 0) {
#ifdef DEBUG_MODE
            xprintf(
                "[ENCLAVE] Encrypted File Successfully Closed during Append");
#endif
        }
        else {
            xprintf("Error while closing file...");
        }
        if (c_fsize > 1)
            free(data);

        return 2;
    } catch (...) {
        xprintf("Error while parsing json in append");
    }
}

inline int
UsersStorage::remove(std::string uuid_2_rm)
{
    std::string filename = "/SecureDBdata/users.keys";

    auto it = USERSENTRIES.find(uuid_2_rm);
    if (it == USERSENTRIES.end()) {
        xprintf("[KEYSTORAGE - USERS] ERROR - The user key does not exist! "
                "Cannot remove!",
                uuid_2_rm.c_str());
        return -2;
    }

    USERSENTRIES.erase(it);

    SGX_FILE *handler = sgx_fopen_auto_key(filename.c_str(), "r");
    if (handler == NULL) {
#ifdef DEBUG_MODE
        xprintf(
            "[KEYSTORAGE - USERS] ERROR Opening Encrypted File during Load");
#endif
        return -1;
    }

    sgx_fseek(handler, 0, SEEK_END);
    long c_fsize = sgx_ftell(handler) + 1;
    sgx_fseek(handler, 0, SEEK_SET);

    char *data = (char *)malloc(c_fsize + 1);
    sgx_fread(data, c_fsize, 1, handler);
    sgx_fclose(handler);

    try {
        json storage_doc = json::parse(data);
        auto iter = storage_doc.begin();
        for (; iter != storage_doc.end();) {

            std::string uuid = iter.value()["uuid"].get<std::string>();

            if (uuid == uuid_2_rm) {
                storage_doc.erase(iter);
                break;
            }
            else {
                ++iter;
            }
        }

        handler = sgx_fopen_auto_key(filename.c_str(), "w");
        sgx_fwrite(storage_doc.dump().c_str(), storage_doc.dump().size() + 1, 1,
                   handler);
        sgx_fflush(handler);

        xprintf("[KEYSTORAGE - USERS] Keys removed for user: %s",
                uuid_2_rm.c_str());
        if (sgx_fclose(handler) == 0) {
#ifdef DEBUG_MODE
            xprintf(
                "[ENCLAVE] Encrypted File Successfully Closed during Append");
#endif
        }
        else {
            xprintf("Error while closing file...");
        }
    } catch (...) {
        xprintf("Error while parsing stored doc");
        return -1;
    }

    free(data);
    return 2;
}

inline bool
UsersStorage::exist(std::string uuid)
{
    auto it = USERSENTRIES.find(uuid);
    if (it == USERSENTRIES.end()) {
        return false;
    }
    else {
        return true;
    }
}

inline std::string
UsersStorage::getAll()
{
    json jdoc;
    auto allarr = json::array();
    for (auto const &pair : USERSENTRIES) {
        std::string result = "{\"uuid\":\"" + pair.first + "\",\"key_data\":\""
                             + pair.second + "\"}";
        allarr.push_back(result.c_str());
    }
    jdoc["all_users"] = allarr;
    return jdoc.dump();
}

inline std::string
UsersStorage::getRole(std::string uuid)
{
    std::string result = "";
    if (exist(uuid)) {
        auto entry = USERSENTRIES[uuid];
        using json = nlohmann::json;
        try {
            json d = json::parse(entry);
            result = d["role"].get<std::string>();
        } catch (...) {
            xprintf("Error in parsing the user entry from the storage system");
            result = "";
        }
    }

    return result;
}

inline std::string
UsersStorage::getEmail(std::string uuid)
{
    std::string result = "";
    if (exist(uuid)) {
        auto entry = USERSENTRIES[uuid];
        using json = nlohmann::json;
        try {
            json d = json::parse(entry);
            result = d["email"].get<std::string>();
        } catch (...) {
            xprintf("Error in parsing the user entry from the storage system");
            result = "";
        }
    }

    return result;
}