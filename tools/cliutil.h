/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef CLIUTIL_H
#define CLIUTIL_H

#include <vector>
#include <string>
#include <iosfwd>
#include <stdexcept>
#include <map> // for std::pair

#include <epicsTime.h>

#include <pvxs/data.h>
#include <utilpvt.h>

namespace pvxs {

struct ArgVal {
    std::string value;
    bool defined = false;

    ArgVal() = default;
    ArgVal(std::nullptr_t) {}
    ArgVal(const std::string& value) :value(value), defined(true) {}
    ArgVal(const char* value) :value(value), defined(true) {}

    inline explicit
    operator bool() const { return defined; }

    inline
    const std::string& operator*() const {
        if(defined)
            return value;
        throw std::logic_error("Undefined argument value");
    }

    template<typename V>
    inline
    V as() const {
        return parseTo<V>(**this);
    }
};

bool operator==(const ArgVal& rhs, const ArgVal& lhs);

struct GetOpt {
    GetOpt(int argc, char *argv[], const char *spec);

    const char *argv0;
    std::vector<std::string> positional;
    std::vector<std::pair<char, ArgVal>> arguments;
    bool success = false;
};

struct NTXCLI {
    std::string name;
    const Value& value;
    epicsTimeStamp reftime;
    Value::Fmt::format_t format = Value::Fmt::Delta;
    uint64_t arrLimit = uint64_t(-1);

    explicit
    NTXCLI(const Value& value) :value(value) {}
};

std::ostream& operator<<(std::ostream& strm, const NTXCLI& ntx);

} // namespace pvxs

#endif // CLIUTIL_H
