/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <map>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/evp.h>

#include <pvxs/sharedpv.h>

#include <evhelper.h>
#include <ossl.h>
#include <utilpvt.h>
#include "minicms.h"

#define NID_SPvaCertStatusURIID "1.3.6.1.4.1.37427.1"
#define SN_SPvaCertStatusURI "ASN.1 - SPvaCertStatusURI"
#define LN_SPvaCertStatusURI "EPICS SPVA Certificate Status URI"

namespace pvxs {

namespace ossl {
template<>
struct ssl_delete<unsigned char> {
    inline void operator()(unsigned char *buf) { if(buf) OPENSSL_free(buf); }
};
#define DEFINE_DELETE(TYPE) \
template<> \
    struct ssl_delete<TYPE> { \
        inline void operator()(TYPE* fp) { if(fp) TYPE ## _free(fp); } \
}
DEFINE_DELETE(BIO);
DEFINE_DELETE(X509);
DEFINE_DELETE(EVP_MD);
DEFINE_DELETE(EVP_PKEY);
DEFINE_DELETE(ASN1_IA5STRING);
DEFINE_DELETE(OCSP_BASICRESP);
DEFINE_DELETE(OCSP_CERTID);
DEFINE_DELETE(OCSP_RESPONSE);
#undef DEFINE_DELETE
#define DEFINE_SK_DELETE(TYPE) \
template<> \
    struct ssl_delete<STACK_OF(TYPE)> { \
        inline void operator()(STACK_OF(TYPE)* fp) { if(fp) sk_ ## TYPE ## _free(fp); } \
}
DEFINE_SK_DELETE(X509);
#undef DEFINE_SK_DELETE

template<typename T>
using ossl_ptr = owned_ptr<T, ssl_delete<T>>;

namespace {
void* s2i_CertStatusPV(const X509V3_EXT_METHOD *method,
                       X509V3_CTX *ctx,
                       const char *str) noexcept
{
    // need to cast away const-ness of method circa openssl 3.0 :(
    return s2i_ASN1_UTF8STRING((X509V3_EXT_METHOD*)method, ctx, str);
}

X509V3_EXT_METHOD CertStatusPV = {
    NID_undef, // dynamic allocation below
    0,
    ASN1_ITEM_ref(ASN1_IA5STRING),
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &s2i_CertStatusPV,
};
void CertStatusPVSetup() {
    if(CertStatusPV.ext_nid!=NID_undef)
        return;

    CertStatusPV.ext_nid = OBJ_create(NID_SPvaCertStatusURIID, SN_SPvaCertStatusURI, LN_SPvaCertStatusURI);
    if(CertStatusPV.ext_nid == NID_undef)
        throw SSLError("Unable to create OBJ_SPvaCertStatusURI");

    if(!X509V3_EXT_add(&CertStatusPV))
        throw SSLError("X509V3_EXT_add");
}

// extra status PV name from cert.
// returns empty string if extension not present.
// non-empty string with PV name
// throws on error
std::string lookupPV(const X509* cert)
{
    auto idx(X509_get_ext_by_NID(cert, CertStatusPV.ext_nid, -1));
    if(idx<0)
        return ""; // not present

    auto ext(X509_get_ext(cert, idx)); // borrowed ref.
    if(!ext)
        throw SSLError("X509_get_ext");

    auto extdata(X509_EXTENSION_get_data(ext));
    if(!extdata)
        throw SSLError("X509_EXTENSION_get_data");

    ossl_ptr<ASN1_IA5STRING> extstr;
    {
        auto extval(ASN1_STRING_get0_data(extdata));
        auto extlen(ASN1_STRING_length(extdata));
        if(!extval || extlen<1)
            throw std::logic_error("X509_EXTENSION data1");

        ossl_ptr<ASN1_IA5STRING> temp(__FILE__, __LINE__,
                                      d2i_ASN1_IA5STRING(nullptr, &extval, extlen));
        extstr = std::move(temp);
    }

    auto extval(ASN1_STRING_get0_data(extstr.get()));
    auto extlen(ASN1_STRING_length(extstr.get()));
    if(!extval || extlen<1)
        throw std::logic_error("X509_EXTENSION data2");

    return {(const char*)extval, size_t(extlen)};
}

Value makeStatusType() {
    using namespace members;
    return TypeDef(TypeCode::Struct, {
        UInt8A("ocsp_response"),
    }).create();
}

struct Entry {
    MiniCMS::Pvt& pvt;
    ossl_ptr<X509> cert;
    server::SharedPV pv;

    Entry(MiniCMS::Pvt& pvt, ossl_ptr<X509>&& cert)
        :pvt(pvt)
        ,cert(std::move(cert))
        ,pv(server::SharedPV::buildReadonly())
    {}

    void update(MiniCMS::sts_t next);
};

} // namespace
} // namespace ossl

struct MiniCMS::Pvt final : public server::Source {
    const Value statusPrototype;
    const ossl::ossl_ptr<EVP_PKEY> pkey;
    const ossl::ossl_ptr<X509> signer;
    const ossl::ossl_ptr<STACK_OF(X509)> chain;

    std::map<std::string, ossl::Entry> certs;

    Pvt(EVP_PKEY *pkey, X509 *signer, STACK_OF(X509) *chain)
        :statusPrototype(ossl::makeStatusType())
        ,pkey(__FILE__, __LINE__, [&]() -> EVP_PKEY* {
            if(1!=EVP_PKEY_up_ref(pkey))
                throw std::logic_error("EVP_PKEY_up_ref");
            return pkey;
        }())
        ,signer(__FILE__, __LINE__, [&]() -> X509* {
            if(1!=X509_up_ref(signer))
                throw std::logic_error("X509_up_ref");
            return signer;
        }())
        ,chain(__FILE__, __LINE__, sk_X509_dup(chain))
    {
        threadOnce<&ossl::CertStatusPVSetup>();
    }

    virtual void onSearch(Search& op) override final;
    virtual void onCreate(std::unique_ptr<server::ChannelControl>&& op) override final;
};

MiniCMS::MiniCMS(EVP_PKEY *pkey, X509 *signer, STACK_OF(X509) *chain)
    :pvt(std::make_shared<Pvt>(pkey, signer, chain))
{}

MiniCMS::~MiniCMS() {}

std::string MiniCMS::enrole(X509 *cert)
{
    auto id(ossl::lookupPV(cert));

    if(!id.empty()) {
        if(pvt->certs.find(id) != pvt->certs.end())
            throw std::runtime_error(SB()<<"Already registered: "<<escape(id));

        if(1!=X509_up_ref(cert))
            throw std::logic_error("X509_up_ref");
        ossl::ossl_ptr<X509> subj(__FILE__, __LINE__, cert);

        auto it = pvt->certs.emplace(std::piecewise_construct,
                               std::forward_as_tuple(id),
                               std::forward_as_tuple(*pvt, std::move(subj)));
        assert(it.second);

        it.first->second.update(Unknown);
    }
    return id;
}

void MiniCMS::attest(const std::string &subjId, sts_t sts)
{
    auto it(pvt->certs.find(subjId));
    if(it==pvt->certs.end())
        return;

    it->second.update(sts);
}

std::shared_ptr<pvxs::server::Source> pvxs::MiniCMS::source() const
{
    return pvt;
}

namespace ossl {
namespace {

constexpr unsigned expire_days = 1;

void Entry::update(MiniCMS::sts_t nextsts) {
    ossl_ptr<OCSP_BASICRESP> rep(__FILE__, __LINE__, OCSP_BASICRESP_new());

    ossl_ptr<EVP_MD> digest(__FILE__, __LINE__,
                            EVP_MD_fetch(nullptr, "SHA2-256", nullptr));

    ossl_ptr<OCSP_CERTID> certid(__FILE__, __LINE__,
                                 OCSP_cert_to_id(digest.get(), cert.get(), pvt.signer.get()));

    ossl_ptr<ASN1_TIME> now(__FILE__, __LINE__,
                            X509_gmtime_adj(NULL, 0)),
        next(__FILE__, __LINE__,
             X509_gmtime_adj(NULL, expire_days*24*60*60));
    // not revoking...
    int revreason = OCSP_REVOKED_STATUS_NOSTATUS;
    ASN1_TIME *revtime = nullptr;
    auto sign = OCSP_basic_add1_status(rep.get(), certid.get(), V_OCSP_CERTSTATUS_GOOD,
                                       revreason, revtime, now.get(), next.get());
    if(!sign)
        throw SSLError("OCSP_basic_add1_status");

    // OCSP_NOCERTS - response assumed signed by issuer, so all necessary
    //                certs included in regular verification chain.
    if(!OCSP_basic_sign(rep.get(), pvt.signer.get(), pvt.pkey.get(),
                        digest.get(), pvt.chain.get(), OCSP_NOCERTS))
        throw SSLError("OCSP_basic_sign_ctx");

    ossl_ptr<OCSP_RESPONSE> resp(__FILE__, __LINE__,
                                 OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL,
                                                      rep.get()));

    ossl_ptr<unsigned char> buf;
    auto buflen = i2d_OCSP_RESPONSE(resp.get(), buf.acquire());
    if(buflen<=0)
        throw SSLError("i2d_OCSP_RESPONSE");

}
}
}

} // namespace pvxs
