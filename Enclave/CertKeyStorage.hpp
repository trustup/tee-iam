#pragma once

#include "Enclave.h"  /* ocalls */
#include <map>
#include <string>
#include <vector>
#include "sgx_tprotected_fs.h"
#include "Types.h"
#include "Enclave_t.h"  /* print_string */


class CertKeyStorage {
private:
	int environment;
	std::string buf_xmargin_client_cert;
	std::string buf_xmargin_client_key;
	std::string buf_xmargin_server_key;
	std::string buf_xmargin_server_cert;

	std::string ca_cert;
	std::string chain_cert;
	std::string Read(std::string filename);
public:
	CertKeyStorage(){};
	CertKeyStorage(int environment);
	void LoadCerts();
	std::string GetClientCert();
	std::string GetServerCert();
	std::string GetClientKey();
	std::string GetServerKey();
	std::string GetChain();
	std::string GetCA();

};

inline void CertKeyStorage::LoadCerts() {
	std::string base_path;
    switch (environment){
    case 0: //primary1
        base_path="/certs/live/primary1.xmargin.io/";
		break;
    case 1: //pre
		base_path="/certs/live/pre.xmargin.io/";
		break;
    case 2: //api
		base_path="/certs/live/api.xmargin.io/";
		break;
	case 3: //pre-dr
		base_path="/certs/live/pre-dr.xmargin.io/";
		break;
	case 4: //api-dr
		base_path="/certs/live/api-dr.xmargin.io/";
		break;
	default:
		xprintf("Variable CURR_ENV not set");
    } 

	buf_xmargin_server_cert=Read(base_path+"cert.pem");
	buf_xmargin_server_key=Read(base_path+"privkey.pem");
	chain_cert=Read(base_path+"fullchain.pem");;
}

inline  CertKeyStorage::CertKeyStorage(int env) {
	environment=env;
}



inline std::string CertKeyStorage::Read(std::string file) {
	std::string filename = file+".enc"; 
	char * data;
	// SGX_FILE* handler = sgx_fopen_auto_key(filename.c_str(), "r");
	// if (handler == NULL) { 
		xprintf("[ENCLAVE] Encrypted key file missing. Generating now!");
		unsigned int size_key_file = 0;

		ocall_ftell(&size_key_file, file.c_str());

		data = (char *) malloc(sizeof(char)*size_key_file+1);
		data[size_key_file]='\0';
		ocall_fread(file.c_str(), data, size_key_file);
		// handler=sgx_fopen_auto_key(filename.c_str(),"w");
		// if (handler == NULL) {
		// 	xprintf("[ENCLAVE] Cannot write Encrypted key file. Error while opening the file");
		// 	return "";
		// }

		// sgx_fwrite(data, strlen(data), 1, handler);
		// sgx_fflush(handler);
	#ifdef DEBUG_MODE
		xprintf("[ENCLAVE] Data Written! Removing Clear File");
	#endif 
		// ocall_fremove(file);

		// if (sgx_fclose(handler))
		// 	xprintf("[ENCLAVE] Encrypted Coded List Successfully Closed");
	// } else {

	// 	sgx_fseek(handler, 0, SEEK_END);
	// 	long fsize = sgx_ftell(handler);
	// 	sgx_fseek(handler, 0, SEEK_SET);
		
	// 	data = (char *) malloc(fsize);

	// 	sgx_fread(data, fsize, 1, handler);

	// 	if (sgx_fclose(handler))
	// 		xprintf("[ENCLAVE] Encrypted Coded List Successfully Closed");
	// }

	std::string result=data;
	free(data);
	return result;
}

inline std::string CertKeyStorage::GetServerCert(){
	return buf_xmargin_server_cert;
}
inline std::string CertKeyStorage::GetServerKey(){
	return buf_xmargin_server_key;
}
inline std::string CertKeyStorage::GetClientCert(){
	return buf_xmargin_client_cert;
}
inline std::string CertKeyStorage::GetClientKey(){
	return buf_xmargin_client_key;
}
inline std::string CertKeyStorage::GetChain(){
	return chain_cert;
}
inline std::string CertKeyStorage::GetCA(){
	return ca_cert;
}