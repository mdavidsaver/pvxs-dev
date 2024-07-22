/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <testMain.h>

#include <epicsUnitTest.h>
#include <epicsEvent.h>

#include <pvxs/unittest.h>
#include <pvxs/log.h>

#include "nlsock.h"

using namespace pvxs;

namespace {

void testrtnl() {
    testDiag("%s", __func__);

    nl::NLSocket sock(NETLINK_ROUTE);

    {
        const struct {
            nlmsghdr hdr;
            ifinfomsg ifi;
            alignas(4)
            rtattr at_mask;
            in_addr_t mask;
        } request = {
            {
                sizeof(request),
                RTM_GETLINK,
                NLM_F_REQUEST|NLM_F_DUMP,
                0,0
            },
            {},
            {
                RTA_LENGTH(sizeof(request.mask)),
                IFLA_EXT_MASK
            },
            RTEXT_FILTER_VF|RTEXT_FILTER_SKIP_STATS,
        };

        epicsEvent done;
        nl::Reply reply;
        auto op(sock.request(request.hdr, [&](nl::Reply&& r){
                    if(r.is_last()) {
                        reply = std::move(r);
                        done.trigger();
                    } else {
                        auto reply(r.reply());
                        auto p(reply.split_as<ifinfomsg>());
                        testDiag("ifindex=%d", p.first.ifi_index);
                        while(auto attr = p.second.next()) {

                        }
                    }
                }));
        testTrue(done.wait(100.0))<<"wait for LO4 lookup";
        testTrue(reply && reply.is_ok())<<"GETLINK dump success";
    }
}

} // namespace

MAIN(testnlsock) {
    testPlan(0);
    testSetup();
    logger_config_env();
    testrtnl();
    cleanup_for_valgrind();
    return testDone();
}
