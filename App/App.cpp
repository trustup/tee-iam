#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include <thread>
#include <unistd.h>
/* Use Debug SGX ? */
#if _DEBUG
#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
#define DEBUG_VALUE 1
#endif

#include <ctime>
#include <iomanip>
#include <chrono>
#include "Comm/sgx-httplib.h"
#include <mutex>
#include "sgx_urts.h"

#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

spdlog::logger *logger = nullptr;
std::mutex mtx;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct func_args {
    int argc;
    char **argv;
    int return_code;
} func_args;

static std::time_t time_now = std::time(nullptr);

std::string
getEnvVar(std::string const &key)
{
    char const *val = getenv(key.c_str());
    return val == NULL ? std::string() : std::string(val);
}

int
main(int argc, char *argv[]) /* not using since just testing w/ wc_test */
{
    try {
        auto console_sink =
            std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::debug);
        // console_sink->set_pattern("[%^%l%$] %v");

        auto file_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>(
            "/data/kms/logs/exec.log", 0, 1);
        file_sink->set_level(spdlog::level::debug);

        logger = new spdlog::logger("multi_sink", { console_sink, file_sink });
        logger->set_level(spdlog::level::trace);

        // spdlog::set_default_logger(logger);
    } catch (const spdlog::spdlog_ex &ex) {
        std::cout << "Log init failed: " << ex.what() << std::endl;
    }

    sgx_launch_token_t t;

    int ret = 0;
    int sgxStatus = 0;
    int updated = 0;
    func_args args = { 0 };

    memset(t, 0, sizeof(sgx_launch_token_t));
    memset(&args, 0, sizeof(args));

    ret = sgx_create_enclave(ENCLAVE_FILENAME, DEBUG_VALUE, &t, &updated,
                             &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        logger->error("Failed to create Enclave : error {}", ret);
        return 1;
    }

    ecall_init_kms(global_eid, 0);

    httplib::SSLServer svr("", "");

    svr.Post("/accesshandler/signup", [&](const auto &req, auto &res) {
        const std::lock_guard<std::mutex> lock(mtx);
        logger->info("Request received for SIGNUP");
        int res_;
        ecall_signup(global_eid, &res_);
        res.set_header("Access-Control-Allow-Origin",
                       req.get_header_value("Origin").c_str());
        res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
        res.set_header(
            "Access-Control-Allow-Headers",
            "X-Requested-With, Content-Type, Accept, Origin, Authorization");
        res.set_header("Access-Control-Allow-Methods",
                       "OPTIONS, GET, POST, HEAD");
        if (res_ == 2) {
            logger->info("SIGNUP OK!");
            res.set_content("{\"status\":\"ok\"}", "text/plain");
        }
        else if (res_ == -2) {
            logger->error("SIGNUP Failed - User already existing");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"user-already-existent\"}",
                "text/plain");
        }
        else if (res_ == -5) {
            logger->error(
                "SIGNUP Failed - Some fields missing in the JSON request");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"missing-request-field\"}",
                "text/plain");
        }
        else {
            logger->error("SIGNUP Failed - Unknown");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"invalid-keys\"}",
                "text/plain");
        }
    });

    svr.Post("/accesshandler/signin", [&](const auto &req, auto &res) {
        const std::lock_guard<std::mutex> lock(mtx);
        logger->info("Request received for SIGNIN");
        int res_;
        ecall_signin(global_eid, &res_);
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
        res.set_header(
            "Access-Control-Allow-Headers",
            "X-Requested-With, Content-Type, Accept, Origin, Authorization");
        res.set_header("Access-Control-Allow-Methods",
                       "OPTIONS, GET, POST, HEAD");

        if (res_ == 2) {
            char *role = (char *)malloc(4096);
            ecall_get_role(global_eid, role, 4096);
            std::string r = role;
            free(role);

            logger->info("SIGNIN OK - Sending 2FA code");
            res.set_content("{\"status\":\"ok\",\"role\":\"" + r + "\"}",
                            "text/plain");
        }
        else if (res_ == -2) {
            logger->error("SIGNIN Failed - User already signed in");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"user-already-signedin\"}",
                "text/plain");
        }
        else if (res_ == -5) {
            logger->error(
                "SIGNIN Failed - Some field missing in the JSON request");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"missing-request-field\"}",
                "text/plain");
        }
        else {
            logger->error("SIGNIN Failed - User not found");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"user-not-found\"}",
                "text/plain");
        }
    });

    svr.Post("/accesshandler/twofactor", [&](const auto &req, auto &res) {
        const std::lock_guard<std::mutex> lock(mtx);
        logger->info("Request received for 2FA");
        int res_;
        ecall_2fa(global_eid, &res_);
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
        res.set_header(
            "Access-Control-Allow-Headers",
            "X-Requested-With, Content-Type, Accept, Origin, Authorization");
        res.set_header("Access-Control-Allow-Methods",
                       "OPTIONS, GET, POST, HEAD");

        if (res_ == 2) {
            logger->info("2FA OK");
            res.set_content("{\"status\":\"ok\"}", "text/plain");
        }
        else {
            logger->error("2FA Failed - Wrong Code");
            res.set_content("{\"status\":\"failed\",\"reason\":\"wrong-code\"}",
                            "text/plain");
        }
    });

    svr.Post("/accesshandler/signout", [&](const auto &req, auto &res) {
        const std::lock_guard<std::mutex> lock(mtx);
        logger->info("Request received for SINGOUT");
        int res_;
        ecall_signout(global_eid, &res_);
        res.set_header("Access-Control-Allow-Origin",
                       req.get_header_value("Origin").c_str());
        res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
        res.set_header(
            "Access-Control-Allow-Headers",
            "X-Requested-With, Content-Type, Accept, Origin, Authorization");
        res.set_header("Access-Control-Allow-Methods",
                       "OPTIONS, GET, POST, HEAD");
        if (res_ == 2) {
            logger->info("SIGNOUT OK!");
            res.set_content("{\"status\":\"ok\"}", "text/plain");
        }
        else if (res_ == -2) {
            logger->error("SIGNOUT Failed - User not signed in");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"user-not-signedin\"}",
                "text/plain");
        }
        else {
            logger->error("SIGNOUT Failed - User not found");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"user-not-found\"}",
                "text/plain");
        }
    });

    svr.Post("/accesshandler/remove", [&](const auto &req, auto &res) {
        const std::lock_guard<std::mutex> lock(mtx);
        logger->info("Request received for REMOVE");
        int res_;
        ecall_remove(global_eid, &res_);
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
        res.set_header(
            "Access-Control-Allow-Headers",
            "X-Requested-With, Content-Type, Accept, Origin, Authorization");
        res.set_header("Access-Control-Allow-Methods",
                       "OPTIONS, GET, POST, HEAD");
        if (res_ == 2) {
            logger->info("REMOVE OK!");
            res.set_content("{\"status\":\"ok\"}", "text/plain");
        }
        else if (res_ == -2) {
            logger->error("REMOVE Failed - User not existent");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"user-not-existent\"}",
                "text/plain");
        }
        else {
            logger->error("REMOVE Failed - Unknown");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"invalid-keys\"}",
                "text/plain");
        }
    });

    svr.Post("/accesshandler/serviceaccess", [&](const auto &req, auto &res) {
        const std::lock_guard<std::mutex> lock(mtx);
        logger->info("Request received for SERVICEACCESS");
        int res_;
        ecall_signup(global_eid, &res_);
        res.set_header("Access-Control-Allow-Origin",
                       req.get_header_value("Origin").c_str());
        res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
        res.set_header(
            "Access-Control-Allow-Headers",
            "X-Requested-With, Content-Type, Accept, Origin, Authorization");
        res.set_header("Access-Control-Allow-Methods",
                       "OPTIONS, GET, POST, HEAD");
        if (res_ == 2) {
            logger->info("SIGNUP OK!");
            res.set_content("{\"status\":\"ok\"}", "text/plain");
        }
        else if (res_ == -2) {
            logger->error("SIGNUP Failed - User already existing");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"user-already-existent\"}",
                "text/plain");
        }
        else {
            logger->error("SIGNUP Failed - Unknown");
            res.set_content(
                "{\"status\":\"failed\",\"reason\":\"invalid-keys\"}",
                "text/plain");
        }
    });

    // //************************************************************************************************
    // //************************************************************************************************

    svr.listen("0.0.0.0", 8866);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}
