#pragma once

#include <string>
#include <vector>
#include "Enclave.h"
#include "Enclave_t.h"
#include <stdlib.h>
#include <cstring>
#include <unistd.h>
#include "jsonsgx.hpp"

extern std::string json_message_rcvd;
extern std::string uuid;
extern std::string received_code;

inline int
handle_http_read(const char *jsonmsg)
{
    using json = nlohmann::json;

    try {
        auto document = json::parse(jsonmsg);
        xprintf("Received: %s\n\n", jsonmsg);
        if (document.contains("uuid")) {
            json_message_rcvd = jsonmsg;
            uuid = document["uuid"].get<std::string>();
        }
        if (document.contains("code")) {
            json_message_rcvd = jsonmsg;
            received_code = document["code"].get<std::string>();
        }
        return 1;
    } catch (...) {
        xprintf("ERROR while parsing in handle_json_msg");
    }
    return -1;
}
