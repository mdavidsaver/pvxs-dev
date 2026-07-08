/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>
#include <iostream>
#include <memory>
#include <sstream>
#include <set>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

#include "cliutil.h"

using namespace pvxs;

namespace {

template<typename T>
struct ssl_delete;
#define DEFINE_DELETE(TYPE) \
template<> \
    struct ssl_delete<TYPE> { \
        inline void operator()(TYPE* fp) { if(fp) TYPE ## _free(fp); } \
}
#define DEFINE_SK_DELETE(TYPE) \
template<> \
    struct ssl_delete<STACK_OF(TYPE)> { \
        inline void operator()(STACK_OF(TYPE)* fp) { if(fp) sk_ ## TYPE ## _free(fp); } \
}
DEFINE_DELETE(BIO);
DEFINE_DELETE(ASN1_OBJECT);
DEFINE_DELETE(X509);
DEFINE_DELETE(X509_ATTRIBUTE);
DEFINE_DELETE(EVP_PKEY);
DEFINE_DELETE(PKCS12);
DEFINE_SK_DELETE(X509);
DEFINE_SK_DELETE(X509_ATTRIBUTE);
#undef DEFINE_DELETE
#undef DEFINE_SK_DELETE

struct SSLError : public std::runtime_error {
    explicit
        SSLError(const std::string& msg)
        :std::runtime_error([&msg]() -> std::string {
            std::ostringstream strm;
            const char *file = nullptr;
            int line = 0;
            const char *data = nullptr;
            int flags = 0;
            while(auto err = ERR_get_error_all(&file, &line, nullptr, &data, &flags)) {
                strm<<file<<':'<<line<<':'<<ERR_reason_error_string(err);
                if(data && (flags&ERR_TXT_STRING))
                    strm<<':'<<data;
                strm<<", ";
            }
            strm<<msg;
            return strm.str();
        }())
    {}
    virtual ~SSLError() {}
};

// ~= std::unique_ptr with a NULL check in the ctor
template<typename T>
struct owned_ptr : public std::unique_ptr<T, ssl_delete<T>>
{
    constexpr owned_ptr() {}
    constexpr owned_ptr(std::nullptr_t np) : std::unique_ptr<T, ssl_delete<T>>(np) {}
    explicit owned_ptr(T* ptr) : std::unique_ptr<T, ssl_delete<T>>(ptr) {
        if(!*this)
            throw SSLError(SB()<<"Can't alloc "<<typeid(ptr).name());
    }

    // for functions which return a pointer in an argument
    //   int some(T** presult); // store *presult = output
    // use like
    //   owned_ptr<T> x;
    //   some(x.acquire());
    struct acquisition {
        owned_ptr<T>* o;
        T* ptr = nullptr;
        operator T** () { return &ptr; }
        constexpr acquisition(owned_ptr<T>* o) :o(o) {}
        ~acquisition() {
            o->reset(ptr);
        }
    };
    acquisition acquire() { return acquisition{this}; }
};

#ifdef NID_oracle_jdk_trustedkeyusage
// OpenSSL 3.2 will add the ability to set the Java specific trustedkeyusage bag attribute
static int jdk_trust(PKCS12_SAFEBAG *bag, void *cbarg) noexcept {
    auto ptrusted = static_cast<const std::set<X509*>*>(cbarg);
    auto& trusted = *ptrusted;
    try {
        // Only add trustedkeyusage when bag is an X509 cert. with an associated key
        // (when localKeyID is present) which does not already have trustedkeyusage.
        if(PKCS12_SAFEBAG_get_nid(bag)!=NID_certBag
            || PKCS12_SAFEBAG_get_bag_nid(bag)!=NID_x509Certificate
            || !!PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)
            || !!PKCS12_SAFEBAG_get0_attr(bag, NID_oracle_jdk_trustedkeyusage))
            return 1;

        owned_ptr<X509> cert(PKCS12_SAFEBAG_get1_cert(bag));
        if(trusted.find(cert.get())==trusted.end())
            return 1;

        auto curattrs(PKCS12_SAFEBAG_get0_attrs(bag));
        // PKCS12_SAFEBAG_get0_attrs() returns const.  Make a paranoia copy.
        owned_ptr<STACK_OF(X509_ATTRIBUTE)> newattrs(sk_X509_ATTRIBUTE_deep_copy(
            curattrs, &X509_ATTRIBUTE_dup,&X509_ATTRIBUTE_free
        ));

        owned_ptr<ASN1_OBJECT> trust(OBJ_txt2obj("anyExtendedKeyUsage", 0));
        owned_ptr<X509_ATTRIBUTE> attr(X509_ATTRIBUTE_create(
            NID_oracle_jdk_trustedkeyusage, V_ASN1_OBJECT, trust.get()
        ));

        if(1!=sk_X509_ATTRIBUTE_push(newattrs.get(), attr.get()))
            throw SSLError("sk_X509_ATTRIBUTE_push");
        attr.release();

        PKCS12_SAFEBAG_set0_attrs(bag, newattrs.get());
        newattrs.release();

        return 1;
    } catch(std::exception& e){
        std::cerr<<"Error: unable to add JDK trust attribute: "<<e.what()<<"\n";
        return 0;
    }
}
#else // !NID_oracle_jdk_trustedkeyusage
static int jdk_trust(PKCS12_SAFEBAG *bag, void *cbarg) noexcept {return 0;}
static inline
    PKCS12 *PKCS12_create_ex2(const char *pass, const char *name, EVP_PKEY *pkey,
                      X509 *cert, STACK_OF(X509) *ca, int nid_key, int nid_cert,
                      int iter, int mac_iter, int keytype,
                      OSSL_LIB_CTX *ctx, const char *propq,
                      int (*cb)(PKCS12_SAFEBAG *bag, void *cbarg), void *cbarg)
{
    return PKCS12_create_ex(pass, name, pkey, cert, ca,
                            nid_key, nid_cert, iter, mac_iter, keytype,
                            ctx, propq);
}
#endif // NID_oracle_jdk_trustedkeyusage

void usage(const char *argv0)
{
    std::cerr<<"Usage: "<<argv0<<"-O <out.p12> [options]\n"
               "\n"
        "  Assemble PKCS12 file from PEM files.\n"
        "\n"
        "  Options:\n"
        "    -O <out.p12>   - Output PKCS12 file\n"
        "    -K <key.pem>   - Input Key file\n"
        "    -C <cert.pem>  - End Entity x509 certificate file\n"
        "    -U <chain.pem> - Include Untrusted x509 certificate in chain store.\n"
        "    -T <chain.pem> - Include Trusted x509 certificate in chain store.\n"
        "    -F <name>      - Friendly name string.\n"
        ;
}

owned_ptr<BIO> openFile(const char *fname)
{
    owned_ptr<BIO> io(BIO_new(BIO_s_file()));

    if(BIO_read_filename(io.get(), fname)<=0)
        throw SSLError(SB()<<"Unable to open for reading: "<<fname);

    return io;
}

owned_ptr<X509> readCert(const char *fname)
{
    auto io(openFile(fname));
    owned_ptr<X509> ret;

    if(!d2i_X509_bio(io.get(), ret.acquire()))
        throw SSLError(SB()<<"Unable to decode PEM from: "<<fname);

    return ret;
}

owned_ptr<EVP_PKEY> readKey(const char *fname)
{
    auto io(openFile(fname));
    owned_ptr<EVP_PKEY> ret;

    if(!d2i_PrivateKey_bio(io.get(), ret.acquire()))
        throw SSLError(SB()<<"Unable to decode PEM from: "<<fname);

    return ret;
}

} // namespace

int main(int argc, char *argv[])
{
    if(argc<1)
        return 42;

    try {
        std::string outFile;
        std::string friendlyName;
        owned_ptr<EVP_PKEY> eekey;
        owned_ptr<X509> ee;
        owned_ptr<STACK_OF(X509)> chain(sk_X509_new_null());
        std::set<X509*> trusted; // chain certs which are trusted

        GetOpt opts(argc, argv, "hO:K:C:U:T:F:");
        for(auto& pair : opts.arguments) {
            switch(pair.first) {
            case 'h':
                usage(opts.argv0);
                return 0;
            case 'O':
                outFile = *pair.second;
                break;
            case 'K':
                eekey = readKey(pair.second.value.c_str());
                break;
            case 'C':
                ee = readCert(pair.second.value.c_str());
                break;
            case 'U':
            case 'T': {
                auto cert(readCert(pair.second.value.c_str()));
                if(1!=sk_X509_push(chain.get(), cert.get()))
                    throw SSLError("sk_X509_push");
                if(pair.first=='T')
                    trusted.insert(cert.get());
            }
            break;
            case 'F':
                friendlyName = *pair.second;
                break;
            default:
                usage(opts.argv0);
                std::cerr<<"\nUnknown argument: "<<pair.first<<std::endl;
                return 1;
            }
        }

        owned_ptr<PKCS12> p12(PKCS12_create_ex2("",
                                                friendlyName.c_str(),
                                                eekey.get(),
                                                ee.get(),
                                                chain.get(),
                                                0, 0, 0, 0, 0,
                                                nullptr, nullptr,
                                                &jdk_trust, (void*)&trusted));

        owned_ptr<BIO> fp(BIO_new(BIO_s_file()));

        if(BIO_write_filename(fp.get(), (void*)outFile.c_str()))
            throw SSLError(SB()<<"Unable to open output file for writing: "<<outFile);

        return 0;
    }catch(std::exception &e){
        std::cerr<<"Error: "<<e.what()<<std::endl;
        return 2;
    }
}
