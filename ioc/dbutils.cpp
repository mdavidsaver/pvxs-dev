/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>

#include <pvxs/version.h>
#include <utilpvt.h>

#include "dbutils.h"

namespace pvxs {
namespace db {

DBError::DBError(long status, const char *pv, const char *op)
    :std::runtime_error(SB()<<(pv ? pv : "(null)")
                            <<" "<<(op?op:"(null)")
                            <<status)
    ,status(status)
{}

DBError::~DBError() {}

#if EPICS_VERSION_INT < VERSION_INT(3,16,1,0)
pvxs::db::DBEntry::DBEntry(dbCommon *prec)
    :DBEntry()
{
    if(dbFindRecord(&ent, prec->name)!=0)
        throw std::logic_error("Record not found");
}
#endif

bool DBEntry::firstRecord() noexcept
{
    // setup at first record (return false for empty DB)
    return !dbFirstRecordType(&ent) && !dbFirstRecord(&ent);
}

bool DBEntry::nextRecord() noexcept
{
    // step to next record, or first record of next type
    return !dbNextRecord(&ent) || (!dbNextRecordType(&ent) && !dbFirstRecord(&ent));
}

DBChan::DBChan(dbChannel *ch)
    :ch(ch)
{
    if(!ch)
        throw std::bad_alloc();
}

DBChan::DBChan(const char *pv)
{
    ch.reset(dbChannelCreate(pv));
    if(!ch)
        throw std::runtime_error(SB()<<"Bad PV "<<pv);
    if(auto sts = dbChannelOpen(ptr())) {
        throw DBError(sts, pv, "open");
    }
}

void DBChan::get_unlock(short dbr, void *buf, long *opts, size_t *nReq, db_field_log *pfl) const
{
    long lReq = nReq ? *nReq : 1;

    if(auto sts = dbChannelGet(ptr(), dbr, buf, opts, &lReq, pfl))
        throw DBError(sts, (*this)->name, __func__);

    if(nReq)
        *nReq = lReq;
}

void DBChan::get_lock(short dbr, void *buf, long *opts, size_t *nReq, db_field_log *pfl) const
{
    long lReq = nReq ? *nReq : 1;

    if(auto sts = dbChannelGetField(ptr(), dbr, buf, opts, &lReq, pfl))
        throw DBError(sts, (*this)->name, __func__);

    if(nReq)
        *nReq = lReq;
}

void DBChan::put_unlock(short dbr, void *buf, size_t nReq) const
{
    if(auto sts = dbChannelPut(ptr(), dbr, buf, nReq))
        throw DBError(sts, (*this)->name, __func__);
}

void DBChan::put_lock(short dbr, void *buf, size_t nReq) const
{
    if(auto sts = dbChannelPut(ptr(), dbr, buf, nReq))
        throw DBError(sts, (*this)->name, __func__);
}

DBCred::DBCred(const server::ClientCredentials &cc)
{
    auto n = cc.peer.find_first_of(':');
    host = cc.peer.substr(0, n);
    if(cc.method=="ca") {
        n = cc.account.find_last_of('/');
        if(n == std::string::npos) {
            cred.push_back(cc.account);
        } else {
            cred.push_back(cc.account.substr(n+1));
        }
    } else {
        cred.push_back(SB()<<cc.method<<'/'<<cc.account);
    }

    for(const auto& role : cc.roles()) {
        cred.push_back(SB()<<"role/"<<role);
    }
}

void ASClient::update(dbChannel *ch, DBCred &cred)
{
    ASClient temp;
    temp.cli.resize(cred.cred.size(), nullptr);

    for(size_t i=0, N=temp.cli.size(); i<N; i++) {
        /* asAddClient() fails secure to no-permission */
        (void)asAddClient(&temp.cli[i],
                          dbChannelRecord(ch)->asp,
                          dbChannelFldDes(ch)->as_level,
                          cred.cred[i].c_str(),
                          cred.host.data());
    }

    cli.swap(temp.cli);
}

ASClient::~ASClient()
{
    for(auto asc : cli) {
        asRemoveClient(&asc);
    }
}

}} // namespace pvxs::db
