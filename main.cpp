#include <iostream>
#include <set>

#include <Windows.h>
#include <wincrypt.h>

#include "utils.cpp"

using namespace std;

string base_name = "CertificateUtils_";
HCERTSTORE cert_store = NULL;

bool init_cert_store();
const CERT_CONTEXT* search_cert(string domain_name);
bool clear_ecrt();

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
            CertFreeCertificateContext(cert_content);
            cout << "The certificate already exists: " << domain_name.c_str() << endl;
        } else {
            cout << "Certificate added successfully: " << domain_name.c_str() << endl;
        }
    } else {
        if (clear_ecrt()) {
            cout << "Clear Finish" << endl;
        }
        cout << "Please enter any character to exit the program" << endl;
        cin.get();
    }
    return EXIT_SUCCESS;
}

bool init_cert_store() {
    if (NULL != cert_store) {
        CertCloseStore(cert_store, CERT_CLOSE_STORE_FORCE_FLAG);
    }
    cert_store = CertOpenSystemStoreA(NULL, "ROOT");
    if (NULL == cert_store) {
        DWORD err_code = GetLastError();
        cout << "open cert store error: ", print_errmsg(cout, err_code) << endl;;
    }
    return NULL != cert_store;
}

const CERT_CONTEXT* search_cert(string domain_name) {
    domain_name = base_name + domain_name;

    if (!init_cert_store()) {
        return false;
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
        cout << "find cert error: ", print_errmsg(cout, err_code) << endl;;
    }
    return NULL;
}

bool clear_ecrt() {
    CHAR name_buf[64 * 1024];
    set<string> delete_err;

    re_clear_ecrt:
    if (!init_cert_store()) {
        return false;
    }

    const CERT_CONTEXT* cert_content = NULL;
    while ((cert_content = CertEnumCertificatesInStore(cert_store, cert_content)) != NULL) {
        DWORD name_len = CertGetNameStringA(cert_content, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, name_buf, sizeof(name_buf));
        if (name_len <= 0) {
            continue;
        }
        if (delete_err.find(name_buf) != delete_err.cend()) {
            continue;
        }
        if (strncmp(base_name.c_str(), name_buf, base_name.length()) != 0) {
            continue;
        }
        if (CertDeleteCertificateFromStore(cert_content)) {
            cout << "delete success" << ": " << name_buf << endl;
            goto re_clear_ecrt;
        } else {
            delete_err.insert(name_buf);
            cout << "delete error(", print_errmsg(cout, GetLastError()) << ")" << ": " << name_buf << endl;
        }
    }

    DWORD err_code = GetLastError();
    if (err_code != CRYPT_E_NOT_FOUND) {
        cout << "find cert error: ", print_errmsg(cout, err_code) << endl;;
        return false;
    }
    return true;
}