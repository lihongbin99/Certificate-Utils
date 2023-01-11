#include <iostream>
#include <set>

#include <Windows.h>
#include <wincrypt.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "utils.cpp"

using namespace std;

string bast_path = ".\\cert\\";
string base_name = "CertificateUtils_";
string cert_suffix = ".crt";
HCERTSTORE cert_store = NULL;

bool init_cert_store();
const CERT_CONTEXT* search_cert(string domain_name);
bool add_cert(string domain_name);
bool clear_ecrt();

string create_ecrt(string domain_name);

int main(int argc, char** argv) {
    if (argc > 1) {
        string domain_name = argv[1];

        string::size_type first_index = domain_name.find(".");
        string::size_type last_index = domain_name.rfind(".");
        if (first_index == 0 || // 不能以.开头
                last_index == domain_name.length() - 1 || // 不能以.结尾
                last_index == string::npos || // 不能没有.
                domain_name.length() == 1) {// 不能一个.都没有
            cout << "domain error: " << domain_name << endl;
            return EXIT_FAILURE;
        }

        const CERT_CONTEXT* cert_content = search_cert(domain_name);
        if (NULL != cert_content) {
            CertFreeCertificateContext(cert_content);
            cout << "The certificate already exists: " << domain_name.c_str() << endl;
        } else {
            if (!add_cert(domain_name)) {
                return EXIT_FAILURE;
            }
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
        cout << "open cert store error: ", print_errmsg(cout, GetLastError()) << endl;
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

bool add_cert(string domain_name) {
    string cert_file_path = create_ecrt(domain_name);
    if (cert_file_path == "") {
        return false;
    }

    HCERTSTORE disk_cert_store = CertOpenStore(CERT_STORE_PROV_FILENAME_A,
                           X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                           NULL,
                           CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                           cert_file_path.c_str());
    if (NULL == disk_cert_store) {
        cout << "open disk cert store error: ", print_errmsg(cout, GetLastError()) << endl;
        return false;
    }

    const CERT_CONTEXT* cert_file = CertEnumCertificatesInStore(disk_cert_store, NULL);
    if (NULL == cert_file) {
        cout << "open disk cert file error: ", print_errmsg(cout, GetLastError()) << endl;
        CertCloseStore(disk_cert_store, CERT_CLOSE_STORE_FORCE_FLAG);
        return false;
    }

    if (!init_cert_store()) {
        return false;
    }

    if (!CertAddCertificateContextToStore(cert_store, cert_file, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        cout << "Failed to add certificate: ", print_errmsg(cout, GetLastError()) << endl;
        return false;
    }
    return true;
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

string create_ecrt(string domain_name) {
    string issuer = base_name + domain_name;
    X509* x509 = X509_new();

    // 设置证书版本号
    X509_set_version(x509, 2);
    BIGNUM* num = BN_new();
    BN_set_bit(num, 160);
    BN_to_ASN1_INTEGER(num, X509_get_serialNumber(x509));
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);

    // 设置证书颁发者和证书所有者信息
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)issuer.c_str()    , -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char *)"CertificateUtils", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O" , MBSTRING_ASC, (unsigned char *)"CertificateUtils", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L" , MBSTRING_ASC, (unsigned char *)"ShenZhen"        , -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)"GuangDong"       , -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "C" , MBSTRING_ASC, (unsigned char *)"CN"              , -1, -1, 0);
    X509_set_issuer_name(x509, name);

    //添加扩展域
    X509_EXTENSION *ext;
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints     , "critical,CA:true");
    X509_add_ext(x509, ext, -1);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    X509_add_ext(x509, ext, -1);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage             , "critical,digitalSignature,keyCertSign,cRLSign");
    X509_add_ext(x509, ext, -1);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage         , "critical,serverAuth");
    X509_add_ext(x509, ext, -1);
    string subject_alt_name = "DNS.1:" + domain_name;
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name      , subject_alt_name.c_str());
    X509_add_ext(x509, ext, -1);

    // 生成密钥对
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bne, NULL);
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    // 为证书设置公钥和私钥
    X509_set_pubkey(x509, pkey);
    X509_sign(x509, pkey, EVP_sha256());

    CreateDirectory(bast_path.c_str(), NULL);
    string cert_file_path = bast_path + base_name + domain_name + cert_suffix;
    string priv_file_path = bast_path + base_name + domain_name + ".key";
    cert_file_path = replaceAll(cert_file_path, "*", "x");
    priv_file_path = replaceAll(priv_file_path, "*", "x");

    // 保存证书和私钥到文件
    BIO* bp_public = BIO_new_file(cert_file_path.c_str(), "w");
    BIO* bp_private = BIO_new_file(priv_file_path.c_str(), "w");
    int result = PEM_write_bio_X509(bp_public, x509);
    if (result == 1) 
        result = PEM_write_bio_PrivateKey(bp_private, pkey, NULL, NULL, NULL, NULL, NULL);

    // 释放资源
    X509_free(x509);
    EVP_PKEY_free(pkey);
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    BN_free(bne);

    if (result == 1) {
        return cert_file_path;
    } else {
        cout << "Failed to create certificate" << endl;
        return "";
    }
}
