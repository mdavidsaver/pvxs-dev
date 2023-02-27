/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_GROUP_H
#define PVXS_GROUP_H

#include <map>

#include <pvxs/data.h>

#include "dbmanylocker.h"
#include "field.h"

namespace pvxs {
namespace ioc {

class ChannelLocks {
public:
    std::vector<dbCommon*> channels;
    DBManyLock lock;
    ChannelLocks() = default;
};

class Group {
private:
public:
    const std::string name;
    const bool atomicPutGet;
    const bool atomicMonitor;
    std::vector<Field> fields;
    Value valueTemplate;
    ChannelLocks value;
    ChannelLocks properties;

    void show(int level) const;
    Field& operator[](const std::string& fieldName);

    Group(const std::string& name, bool atomicPutGet, bool atomicMonitor)
        :name(name)
        ,atomicPutGet(atomicPutGet)
        ,atomicMonitor(atomicMonitor)
    {}
    Group(const Group&) = delete;
};

} // pvxs
} // ioc

#endif //PVXS_GROUP_H
