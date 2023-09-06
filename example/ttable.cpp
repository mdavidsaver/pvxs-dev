/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/* Table Example for Torsten
 *
 * Publish a static table PV from within an IOC w/ PVXS.
 *
 * eg. run "softIocPVX" and enter:
 *   dlload example/O.linux-x86_64-debug/libttable.so
 *   dbLoadDatabase example/ttable.dbd
 *   registerAllRecordDeviceDrivers
 *   iocInit
 *
 */

#include <exception>

#include <pvxs/iochooks.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/nt.h>

#include <cantProceed.h>
#include <epicsExport.h>
#include <initHooks.h>

namespace {
using namespace pvxs;

void ttableHooks(initHookState state) {
    if(state!=initHookAfterIocRunning)
        return;

    try {
        const auto prototype(nt::NTTable{}
                   .add_column(TypeCode::String, "symbol")
                   .add_column(TypeCode::Float64, "min")
                   .add_column(TypeCode::Float64, "max")
                   .create());

        auto pv(server::SharedPV::buildReadonly());
        pv.open(prototype); // initialize with empty table

        ioc::server()
                .addPV("my:symbol:table", pv);

        // example: prepare an update.
        // would normally happen after init, from other thread(s)
        {
            shared_array<const std::string> syms({"foo", "bar"});
            shared_array<const double> mins({-1.0, 0.0});
            shared_array<const double> maxs({10.0, 20.0});

            auto table(prototype.cloneEmpty());
            table["value.symbol"] = syms;
            table["value.min"] = mins;
            table["value.max"] = maxs;

            pv.post(table);
        }

    }catch(std::exception& e){
        cantProceed("%s fatal error: %s\n", __func__, e.what());
    }
}

void ttableExample() {
    initHookRegister(&ttableHooks);
}

} // namespace

extern "C" {
epicsExportRegistrar(ttableExample);
}
