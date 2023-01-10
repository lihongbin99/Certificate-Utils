#include <iostream>

#include <Windows.h>
#include <wincrypt.h>

#include "utils.cpp"

using namespace std;

HCERTSTORE cert_store = NULL;

const CERT_CONTEXT* search_cert(string domain_name);

int main(int argc, char** argv) {
    if (argc > 1) {
        string domain_name = argv[1];

        string::size_type first_index = domain_name.find(".");
        string::size_type last_index = domain_name.rfind(".");
        if (first_index == 0 || // 不能以.开头
                last_index == domain_name.length() - 1 || // 不能以.结尾
                last_index == string::npos || // 不能没有.
                domain_name.length() == 1) {// 不能只有一个.
            cout << "domain error: " << domain_name << endl;
            return EXIT_FAILURE;
        }

        const CERT_CONTEXT* cert_content = search_cert(domain_name);
        if (NULL != cert_content) {
            // 证书已存在, 无需添加
            CertFreeCertificateContext(cert_content);
            cout << "The certificate already exists: " << domain_name.c_str() << endl;
        } else {
            // TODO 添加证书
            cout << "Certificate added successfully: " << domain_name.c_str() << endl;
        }
    } else {
        // TODO 清除证书
        cout << "Clear Finish" << endl;
        cout << "Please enter any character to exit the program" << endl;
        cin.get();
    }
    return EXIT_SUCCESS;
}

const CERT_CONTEXT* search_cert(string domain_name) {
    domain_name = "CertificateUtils_" + domain_name;

    cert_store = CertOpenSystemStoreA(NULL, "ROOT");
    if (NULL == cert_store) {
        DWORD err_code = GetLastError();
        cout << "open cert store error: ", println_errmsg(err_code);
        return NULL;
    }

    const CERT_CONTEXT* cert_content = NULL;
    CHAR name_buf[64 * 1024];
    while ((cert_content = CertEnumCertificatesInStore(cert_store, cert_content)) != NULL) {
        DWORD name_len = CertGetNameStringA(cert_content, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, name_buf, sizeof(name_buf));
        if (name_len > 0) {
            if (domain_name == name_buf) {
                return cert_content;
            }
        }
    }

    DWORD err_code = GetLastError();
    if (err_code != CRYPT_E_NOT_FOUND) {
        cout << "find cert error: ", println_errmsg(err_code);
    }
    return NULL;
}
