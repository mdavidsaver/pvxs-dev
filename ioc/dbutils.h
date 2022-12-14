/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef DBUTILS_H
#define DBUTILS_H

#include <string>
#include <memory>
#include <vector>
#include <stdexcept>

#include <dbAccess.h>
#include <dbStaticLib.h>
#include <asLib.h>

#include <pvxs/source.h>

// hooks for std::unique_ptr
namespace std {
template<>
struct default_delete<dbChannel> {
    inline void operator()(dbChannel* ch) { if(ch) dbChannelDelete(ch); }
};
} // namespace std

namespace pvxs {namespace db {

struct DBError : public std::runtime_error {
    long status;
    DBError(long status, const char* pv, const char* op);
    virtual ~DBError();
};

class DBEntry {
    DBENTRY ent;
public:
    inline
    DBEntry() noexcept {
        dbInitEntry(pdbbase, &ent);
    }

#if EPICS_VERSION_INT >= VERSION_INT(3,16,1,0)
    inline
    explicit DBEntry(dbCommon *com) noexcept
    {
        dbInitEntryFromRecord(com, &ent);
    }
#else
    explicit DBEntry(dbCommon *com);
#endif

    inline
    explicit DBEntry(const dbChannel *chan) noexcept
        :DBEntry(dbChannelRecord(chan))
    {}

    inline
    ~DBEntry() {
        dbFinishEntry(&ent);
    }

    template<typename Rec=dbCommon>
    inline
    Rec* record() const noexcept {
        static_assert (sizeof(Rec::dpvt)==sizeof(void*),
                "Rec must be dbCommon or specific recordType");
        return ent.precnode ? (Rec*)ent.precnode->precord : nullptr;
    }

    inline
    const char* info(const char* key, const char* def=nullptr) noexcept {
        if(dbFindInfo(&ent, key))
            return def;
        return dbGetInfoString(&ent);
    }

    bool firstRecord() noexcept;
    bool nextRecord() noexcept;
};

struct Records {
    class iterator {
        dbRecordNode *node = nullptr;
    public:
        iterator() = default;

        bool operator==(const iterator& o) const { return node == o.node; }
        bool operator!=(const iterator& o) const { return node != o.node; }
        dbCommon* operator*() const { return (dbCommon*)node->precord; }

        iterator& operator++() noexcept;
        iterator operator++(int) noexcept {
            iterator ret(*this);
            ++(*this);
            return ret;
        }
    };

    iterator begin() const noexcept;
    inline
    iterator end() const { return iterator(); }
};


class DBChan {
    std::unique_ptr<dbChannel> ch;
public:

    DBChan() = default;
    explicit DBChan(dbChannel *ch);
    explicit DBChan(const char *pv);
    inline
    explicit DBChan(const std::string& pv) :DBChan(pv.c_str()) {}

    inline
    explicit operator bool() const noexcept { return ch.operator bool(); }
    inline
    dbChannel& operator*() const noexcept { return *ch; }
    inline
    dbChannel* operator->() const noexcept { return ch.get(); }
    inline
    dbChannel* ptr() const noexcept { return ch.get(); }

    // dbGet()
    void get_unlock(short dbr, void *buf, long *opts, size_t *nReq, db_field_log *pfl) const;
    // dbGetField()
    void get_lock(short dbr, void *buf, long *opts, size_t *nReq, db_field_log *pfl) const;
    void put_unlock(short dbr, void *buf, size_t nReq) const;
    void put_lock(short dbr, void *buf, size_t nReq) const;
};

struct DBCred {
    // eg.
    //  "username"  implies "ca/" prefix
    //  "krb/principle"
    //  "role/groupname"
    std::vector<std::string> cred;
    std::string host;
    explicit DBCred(const server::ClientCredentials& cred);
    DBCred(const DBCred&) = delete;
    DBCred(DBCred&&) = default;
};

struct ASClient {
    std::vector<ASCLIENTPVT> cli;
    ~ASClient();
    void update(dbChannel* ch, DBCred& cred);
};

} // namespace pvxs::db

}

#endif // DBUTILS_H
