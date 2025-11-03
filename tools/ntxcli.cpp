/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#define epicsStdioStdStreams
#define epicsStdioStdPrintfEtc

#include <exception>

#include <epicsTime.h>
#include <epicsStdio.h>

#include "cliutil.h"

namespace pvxs {

namespace {

void render_time_t(std::ostream& strm, const NTXCLI& ntx, const Value& timeStamp)
{
    if(!timeStamp) {
        strm<<"<\?\?\?>";
        return;
    }
    int64_t sec = 0;
    int32_t ns = 0, utag = 0;
    (void)timeStamp["secondsPastEpoch"].as(sec);
    (void)timeStamp["nanoseconds"].as(ns);
    (void)timeStamp["userTag"].as(utag);

    epicsTimeStamp ts;
    ts.secPastEpoch = sec - POSIX_TIME_AT_EPICS_EPOCH;
    ts.nsec = ns;

    auto diff = epicsTimeDiffInSeconds(&ts, &ntx.reftime);

    const char *fmt = "%Y-%m-%dT%H:%M:%S.%9f";
    if(diff < 60*24) { // < 1 day
        fmt = "%H:%M:%S.%9f";
    } else if(diff < 60*24*29) { // < 29 days
        fmt = "%dT%H:%M:%S.%9f";
    }

    char tsbuf[sizeof("2025-10-10T12:34:56.123456789#-abcdef01")];
    auto n = epicsTimeToStrftime(tsbuf, sizeof(tsbuf), fmt, &ts);
    if(utag>0)
        epicsSnprintf(&tsbuf[n], sizeof(tsbuf)-n, "#%X", unsigned(utag));
    else if(utag<0)
        epicsSnprintf(&tsbuf[n], sizeof(tsbuf)-n, "#-%X", unsigned(-utag));

    strm<<tsbuf;
}

void render_alarm_t(std::ostream& strm, const NTXCLI& ntx)
{
    if(!ntx.value)
        return;

    int32_t sevr = 0;
    std::string amsg;
    (void)ntx.value["alarm.severity"].as(sevr);
    (void)ntx.value["alarm.message"].as(amsg);

    if(sevr) {
        const char* sevrlbl = "\?\?\?";
        switch(sevr) {
        case 1: sevrlbl = "MINOR"; break;
        case 2: sevrlbl = "MAJOR"; break;
        case 3: sevrlbl = "INVALID"; break;
        }
        strm<<' '<<sevrlbl<<'('<<sevr<<')';
    }
}

void render_NTScalar(std::ostream& strm, const NTXCLI& ntx)
{
    auto value = ntx.value["value"];
    const auto vtype = value.type();

    if(vtype.isarray() || vtype.kind()==Kind::Compound || vtype.kind()==Kind::Null) {
        strm<<" NTScalar_not_scalar";

    } else if(vtype==TypeCode::String) {
        strm<<' '<<maybeQuote(value.as<std::string>());

    } else {
        strm<<' '<<value;
    }

    if(auto egu = ntx.value["display.units"]) {
        std::string units;
        if(egu.as(units) && !units.empty()) {
            strm<<' '<<maybeQuote(units);
        }
    }

    render_alarm_t(strm, ntx);
    strm.put('\n');
}

template<typename T, typename D=T>
void render_numeric_value(std::ostream& strm, const Value& value)
{
    auto arr(value.as<shared_array<const T>>());
    for(auto elem : arr) {
        strm<<' '<<D(elem);
    }
}

void render_NTScalarArray(std::ostream& strm, const NTXCLI& ntx)
{
    render_alarm_t(strm, ntx);

    auto value = ntx.value["value"];
    const auto vtype = value.type();


    switch(vtype.code) {
    case TypeCode::Int8A: render_numeric_value<int8_t, int16_t>(strm, value); break;
    case TypeCode::Int16A: render_numeric_value<int16_t>(strm, value); break;
    case TypeCode::Int32A: render_numeric_value<int32_t>(strm, value); break;
    case TypeCode::Int64A: render_numeric_value<int64_t>(strm, value); break;

    case TypeCode::UInt8A: render_numeric_value<uint8_t, int16_t>(strm, value); break;
    case TypeCode::UInt16A: render_numeric_value<uint16_t>(strm, value); break;
    case TypeCode::UInt32A: render_numeric_value<uint32_t>(strm, value); break;
    case TypeCode::UInt64A: render_numeric_value<uint64_t>(strm, value); break;

    case TypeCode::Float32A: render_numeric_value<float>(strm, value); break;
    case TypeCode::Float64A: render_numeric_value<double>(strm, value); break;

    case TypeCode::StringA:{
        auto arr(value.as<shared_array<const std::string>>());
        for(const auto& elem : arr) {
            strm<<' '<<maybeQuote(elem);
        }

    }
    break;

    case TypeCode::BoolA: {
        auto arr(value.as<shared_array<const bool>>());
        for(auto elem : arr) {
            strm<<' '<<(elem ? "true" : "false");
        }

    }
    break;

    default:
        strm<<" NTScalarArray_not_scalararray";
        return;
    }

    strm.put('\n');
}

} // namespace

std::ostream& operator<<(std::ostream& strm, const NTXCLI& ntx)
{
    render_time_t(strm, ntx, ntx.value["timeStamp"]);
    strm<<' '<<ntx.name;

    if(!ntx.value) {
        strm<<" NULL\n";

    } else {
        const auto& topid = ntx.value.id();

        if(topid=="epics:nt/NTScalar:1.0") {
            render_NTScalar(strm, ntx);
        } else if(topid=="epics:nt/NTScalarArray:1.0") {
            render_NTScalarArray(strm, ntx);
        } else if(topid=="epics:nt/NTEnum:1.0") {
        } else {
            // TODO: infer NTScalar-like
        }
    }
    return strm;
}

} // namespace pvxs
