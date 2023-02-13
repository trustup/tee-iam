
#include <Poco/Net/AcceptCertificateHandler.h>
#include <Poco/Net/FilePartSource.h>
#include <Poco/Net/InvalidCertificateHandler.h>
#include <Poco/Net/MailMessage.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SecureSMTPClientSession.h>
#include <Poco/Net/SSLManager.h>

#include <iostream>
#include <string>


using namespace std;

void send_email(const char *email, const char *code){
    Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(Poco::Net::Context::CLIENT_USE, "", "", "", Poco::Net::Context::VERIFY_RELAXED, 9, true, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    Poco::Net::MailMessage msg;
    std::cout<<"Sending 2FA email...";
    msg.addRecipient(
         Poco::Net::MailRecipient( Poco::Net::MailRecipient::PRIMARY_RECIPIENT, email, email));
    msg.setSender("INCISIVE Project <incisive.eu.project@gmail.com>");
    msg.setSubject("Authentication Code");
    std::string msg2send =
        "\nDear user,\n\nHere is the code for getting access "
        "to the INCISIVE platform: \n\n"
        + std::string(code);

    msg.setContent(msg2send);

    Poco::Net::SecureSMTPClientSession session = Poco::Net::SecureSMTPClientSession("smtp.gmail.com", 587);
    session.open();
    Poco::Net::initializeSSL();
    try
    {
        session.login();
        if (session.startTLS(ptrContext))
        {
            session.login(Poco::Net::SecureSMTPClientSession::AUTH_LOGIN, "incisive.eu.project@gmail.com", "bigyxrmhkhnwtzqg");
        }
        cout << "Session created and logged in successfully!" << endl;
        session.sendMessage(msg);
        cout << "Message sent!" << endl;
    }
    catch (Poco::Net::SMTPException &e)
    {
        std::cout << e.message() << std::endl;
        session.close();
        Poco::Net::uninitializeSSL();
    }

    session.close();
    Poco::Net::uninitializeSSL();
}
