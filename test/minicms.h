/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef MINICMS_H
#define MINICMS_H

#include <string>
#include <memory>

#include <pvxs/source.h>

#include <openssl/types.h>
#include <openssl/stack.h>

namespace pvxs {

/* Simplest OCSP over PVA Source
 */
struct MiniCMS final {
    MiniCMS() = default;
    MiniCMS(EVP_PKEY *pkey, X509 *signer, STACK_OF(X509) *chain);
    ~MiniCMS();

    enum sts_t {
        Unknown,
        Good,
        Revoke,
    };

    // Enrole a new certificate, returns an ID key.
    // newly enroled key will be in the "unknown" status
    std::string enrole(X509 *cert);

    void attest(const std::string& subjId, sts_t sts);

    std::shared_ptr<pvxs::server::Source> source() const;

    struct Pvt;
private:
    std::shared_ptr<Pvt> pvt;
};

} // namespace pvxs

#endif // MINICMS_H
