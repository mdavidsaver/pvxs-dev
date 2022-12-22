/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#define PVXS_ENABLE_EXPERT_API

#include <testMain.h>
#include <epicsUnitTest.h>
#include <pvxs/unittest.h>

#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/client.h>
#include "evhelper.h"


using namespace pvxs;

namespace {

bool testFwdVia(const server::Config& base, const SockAddr& ifaddr)
{
    testDiag("In %s(%s)", __func__, ifaddr.tostring().c_str());

    auto pv(server::SharedPV::buildMailbox());
    pv.open(nt::NTScalar{TypeCode::UInt32}.create().update("value", 42u));

    server::Server srv1, srv2;
    {
        auto sconf = base;
        sconf.overrideShareUDP(false);
        // unicast through one interface
        sconf.tcp_port = sconf.udp_port = 0;
        if(ifaddr.family()!=AF_UNSPEC)
            sconf.interfaces.push_back(ifaddr.tostring());
        sconf.auto_beacon = false;

        srv1 = sconf.build();

        sconf = srv1.config();
        sconf.overrideShareUDP(false);

        srv2 = sconf.build();
    }

    srv1.addPV("testpv1", pv);
    srv2.addPV("testpv2", pv);

    srv1.start();
    srv2.start();

    auto cli(srv1.clientConfig().build());

    try {
        Value result;
        result = cli.get("testpv1").exec()->wait(5.0);
        testDiag("Success1: %u", (unsigned)result["value"].as<uint32_t>());
        result = cli.get("testpv2").exec()->wait(5.0);
        testDiag("Success2: %u", (unsigned)result["value"].as<uint32_t>());
        return true;

    } catch (client::Timeout&) {
        testDiag("Timeout");
        return false;
    }
}

void testFwdIface()
{
    testDiag("In %s", __func__);

    std::vector<SockAddr> ifaddrs;
    {
        auto& ifs(IfaceMap::instance());

        epicsGuard<epicsMutex> G(ifs.lock);

        for(auto it : ifs.byIndex) {
            auto& iface = it.second;
            if(iface.isLO)
                continue;

            for(auto it2 : iface.addrs) {
                if(it2.first.family()!=AF_INET)
                    continue; // TODO: ipv6 link local addresses don't have scope set
                ifaddrs.emplace_back(it2.first);
            }
        }
    }

    bool ok = false;
    for(auto& ifaddr : ifaddrs) {
        ok |= testFwdVia(server::Config{}, ifaddr);
    }

#if defined(__rtems__) || defined(vxWorks)
    testSkip(1, "local mcast unnecessary with a single OS process");
#else
    testOk(!!ok, "Succeeded via at least one interface");
#endif
}

void testFwdAny()
{
    testDiag("In %s", __func__);

    auto ok = testFwdVia(server::Config{}, SockAddr());
    testOk(ok, "Succeeded via wildcard interface");
}

} // namespace

MAIN(testudpfwd)
{
    SockAttach attach;
    testPlan(0);
    testSetup();
    pvxs::logger_config_env();
    testFwdIface();
    testFwdAny();
    cleanup_for_valgrind();
    return testDone();
}
