#include <Poco/Net/SecureSMTPClientSession.h>
#include <Poco/Net/MailMessage.h>

using namespace Poco::Net;


void send_email(const char *email, const char *code){
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

    SecureSMTPClientSession smtp("smtp.gmail.com");
    smtp.login(SMTPClientSession::AUTH_LOGIN, "incisive.eu.project@gmail.com",
               "Incisive2023");

    smtp.sendMessage(msg);

    smtp.close();
}