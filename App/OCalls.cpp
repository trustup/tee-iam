
#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include <iostream> /* contains include of Enclave_u.h which has wolfSSL header files */
#include <unistd.h>
#include "Comm/sgx-httplib.h"
#include <time.h>
#include <experimental/filesystem>
#include <Poco/Net/SMTPClientSession.h>
#include <Poco/Net/MailMessage.h>

using namespace Poco::Net;
namespace fs = std::experimental::filesystem;

inline void
findAndReplaceAll(std::string &data, std::string toSearch,
                  std::string replaceStr)
{
    // Get the first occurrence
    size_t pos = data.find(toSearch);
    // Repeat till end is reached
    while (pos != std::string::npos) {
        // Replace this occurrence of Sub String
        data.replace(pos, toSearch.size(), replaceStr);
        // Get the next occurrence from the current position
        pos = data.find(toSearch, pos + replaceStr.size());
    }
}

void
ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    logger->info(str);
}

static double
current_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)(1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0;
}

void
ocall_current_time(double *time)
{
    if (!time)
        return;
    *time = current_time();
    return;
}

void
ocall_low_res_time(int *time)
{
    struct timeval tv;
    if (!time)
        return;
    *time = tv.tv_sec;
    return;
}

size_t
ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

size_t
ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

unsigned int
ocall_ftell(const char *filename)
{
    unsigned int retval = 0;
    std::string filename_str = filename;
    if (fs::is_symlink(filename)) {
        filename_str = fs::read_symlink(filename);
        findAndReplaceAll(filename_str, "../../", "/certs/");
    }
    FILE *f = fopen(filename_str.c_str(), "rb");
    if (!f) {
        logger->error("Issues in opening CERTS dir!");
        exit(-1);
    }
    if (fseek(f, 0, SEEK_END) == -1) {
        perror("Could not seek");
        return -1;
    }
    retval = ftell(f);
    rewind(f);
    return retval;
}

void
ocall_fread(const char *filename, char *content, unsigned int size)
{
    std::string filename_str = filename;
    if (fs::is_symlink(filename)) {
        filename_str = fs::read_symlink(filename);
        findAndReplaceAll(filename_str, "../../", "/certs/");
    }
    FILE *f = fopen(filename_str.c_str(), "rb");
    fread(content, size, 1, f);
    fclose(f);
}

void
ocall_fremove(const char *filename)
{
    if (remove(filename) != 0)
        printf("Error deleting file\n");
    else
        printf("File successfully deleted");
}

void
ocall_send_email(const char *email, const char *code)
{
    MailMessage msg;

    msg.addRecipient(
        MailRecipient(MailRecipient::PRIMARY_RECIPIENT, email, email));
    msg.setSender("INCISIVE Project <incisive.eu.project@gmail.com>");
    msg.setSubject("Authentication Code");
    std::string msg2send =
        "\nDear user,\n\nHere is the code for getting access "
        "to the INCISIVE platform: \n\n"
        + std::string(code);
    msg.setContent(msg2send);

    SMTPClientSession smtp("smtp.gmail.com");
    smtp.login(SMTPClientSession::AUTH_LOGIN, "incisive.eu.project@gmail.com",
               "Incisive2023");
    smtp.sendMessage(msg);
    smtp.close();
}