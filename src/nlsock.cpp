/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>
#include <map>
#include <vector>

#include <epicsEvent.h>

#include <pvxs/log.h>
#include "evhelper.h"
#include "nlsock.h"

DEFINE_LOGGER(setup, "pvxs.nl.setup");
DEFINE_LOGGER(io, "pvxs.nl.io");

namespace pvxs {namespace nl {

struct NLSocket::Impl {
    std::weak_ptr<Impl> internal_self;
    uint32_t mypid;
    unsigned maxrx;
    evsocket sock;
    evbase base;
    evevent evt_rx;
    evevent evt_tx;

    uint32_t _next_seq = 0xdeadbeef;
    std::map<uint32_t, std::weak_ptr<Request::Impl>> requests;

    std::deque<std::shared_ptr<std::vector<char>>> todo;

    Impl(int proto)
        :sock(AF_NETLINK, SOCK_DGRAM, proto)
        ,base("nl")
        ,evt_rx(__FILE__, __LINE__,
                event_new(base.base, sock.sock, EV_READ|EV_PERSIST, &onRX, this))
        ,evt_tx(__FILE__, __LINE__,
                event_new(base.base, sock.sock, EV_WRITE, &onTX, this))
    {
        {
            sockaddr_nl addr{};
            addr.nl_family = AF_NETLINK;
            int ret = ::bind(sock.sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
            if(ret!=0) {
                int err = evutil_socket_geterror(sock);
                throw std::system_error(err, std::system_category());
            }
            socklen_t slen = sizeof(addr);
            if(getsockname(sock.sock, reinterpret_cast<sockaddr*>(&addr), &slen)) {
                int err = evutil_socket_geterror(sock);
                throw std::system_error(err, std::system_category());
            }
            mypid = addr.nl_pid;
        }
        {
            int flag = 1;
            if(setsockopt(sock.sock, SOL_NETLINK, NETLINK_NO_ENOBUFS, &flag, sizeof(flag)))
                log_warn_printf(setup, "Unable to set NETLINK_NO_ENOBUFS%s", "\n");
        }
        {
            int flag = 1;
            if(setsockopt(sock.sock, SOL_NETLINK, NETLINK_EXT_ACK, &flag, sizeof(flag)))
                log_warn_printf(setup, "Unable to set NETLINK_EXT_ACK%s", "\n");
        }
        {
            int flag = 1;
            if(setsockopt(sock.sock, SOL_NETLINK, NETLINK_CAP_ACK, &flag, sizeof(flag)))
                log_warn_printf(setup, "Unable to set NETLINK_CAP_ACK%s", "\n");
        }
        {
            socklen_t slen = sizeof(maxrx);
            if(getsockopt(sock.sock, SOL_SOCKET, SO_RCVBUF, &maxrx, &slen) || slen!=sizeof(maxrx))
                throw std::runtime_error(SB()<<"Unable to get NL SO_RCVBUF, "<<SOCKERRNO);
        }

        base.call([this](){
            if(event_add(evt_rx.get(), nullptr))
                throw std::runtime_error("Unable to setup NL RX");
        });
    }

    uint32_t next_seq() {
        if(requests.size()==uint32_t(-1))
            throw std::runtime_error("Too many nl requests");
        while(requests.find(_next_seq)!=requests.end())
            _next_seq++;
        return _next_seq++;
    }

    void queueTX(std::shared_ptr<std::vector<char>>&& buf);

    static
    void onTX(evutil_socket_t fd, short evt, void *raw);

    static
    void onRX(evutil_socket_t fd, short evt, void *raw);
};

struct Request::Impl {
    const uint32_t seq;
    std::weak_ptr<NLSocket::Impl> dispatch;
    std::function<void (Reply &&)> handler;

    Impl(uint32_t seq): seq(seq) {}

    void cancel() {
        if(auto disp = dispatch.lock()) {
            disp->base.tryCall([this, &disp](){
                disp->requests.erase(seq);
            });
        }
    }
};

AttrIter::value_type
AttrIter::next()
{
    auto at = reinterpret_cast<const nlattr*>(cur);
    if(!remaining)
        return value_type{nullptr};
    if(remaining<sizeof(nlattr) || at->nla_len<sizeof(nlattr) || at->nla_len<remaining)
        throw std::runtime_error("Invalid nlattr");

    auto p = reinterpret_cast<const char*>(cur);
    size_t atal = NLA_ALIGN(at->nla_len);
    if(atal>=remaining) {
        remaining -= atal;
        p += atal;
    } else {
        remaining = 0; // last attribute in packet allowed to omit padding...
        p = nullptr;
    }
    cur = p;

    return value_type{at};
}

NLSocket::NLSocket(int proto)
{
    auto internal(std::make_shared<Impl>(proto));
    internal->internal_self = internal;

    impl.reset(internal.get(), [internal](Impl*) mutable {
        auto self(std::move(internal));
        self->base.join();
    });
}

NLSocket::~NLSocket() {}

Request NLSocket::request(const nlmsghdr &msg, std::function<void (Reply &&)> &&cb)
{
    if(!impl)
        throw std::logic_error("NULL");

    auto start = reinterpret_cast<const char*>(&msg);
    auto end = start + msg.nlmsg_len;
    auto tx(std::make_shared<std::vector<char>>(start, end)); // copy

    Request external;

    impl->base.call([this, &external, &tx](){
        // worker thread
        auto internal(std::make_shared<Request::Impl>(impl->next_seq()));
        internal->dispatch = impl->internal_self;

        auto hdr(reinterpret_cast<nlmsghdr*>(tx->data()));
        hdr->nlmsg_seq = internal->seq;
        hdr->nlmsg_pid = 0;

        external.impl.reset(internal.get(), [internal](Request::Impl*) mutable {
            // user thread
            auto self(std::move(internal));
            self->cancel();
        });

        impl->queueTX(std::move(tx));
        impl->requests[internal->seq] = internal;
    });
    external.impl->handler = std::move(cb);

    return external;
}

void NLSocket::request_ack(const nlmsghdr &msg, double timeout)
{
    epicsEvent done;
    Reply result;
    auto req(request(msg, [&](Reply&& reply){
                 result = std::move(reply);
                 done.trigger();
             }));

    if(timeout<0) {
        done.wait();

    } else {
        if(!done.wait(timeout))
            throw std::runtime_error(SB()<<__func__<<" timeout");
    }
    if(!result || !result.is_last()) {
        throw std::logic_error(SB()<<__func__<<" first message is not also last message");
    }
    (void)result.reply();
}

Request NLSocket::listen(std::function<void (Reply &&)> &&)
{
    throw std::logic_error("Not implemented");
}

Request::~Request() {}

void Request::cancel() {
    if(impl)
        impl->cancel();

}

void NLSocket::Impl::queueTX(std::shared_ptr<std::vector<char> > &&buf)
{
    bool wasEmpty = todo.empty();
    todo.push_back(std::move(buf));
    if(wasEmpty && event_add(evt_tx.get(), nullptr))
        log_err_printf(io, "Unable to enable NL TX in %s\n", __func__);
}

void NLSocket::Impl::onTX(int, short, void *raw)
{
    auto self(static_cast<NLSocket*>(raw));
    auto impl(self->impl.get());
    try{
        const sockaddr_nl dest{AF_NETLINK};

        while(!impl->todo.empty()) {
            const auto& buf(impl->todo.front());

            auto n = sendto(impl->sock.sock, buf->data(), buf->size(), 0,
                            reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));

            if(n<0) {
                auto err = SOCKERRNO;
                if(err==EWOULDBLOCK || err==EAGAIN) {
                    // requeue
                    if(event_add(impl->evt_tx.get(), nullptr))
                        log_err_printf(setup, "Error reenabling NL TX\n%s", "");
                    return; // try again later
                }
                // treat as unrecoverable...
                log_err_printf(io, "sendto() Error %d\n", err);
                impl->todo.pop_front();
                return;
            } else if(size_t(n)!=buf->size()) {
                // can this happen with NL?
                log_err_printf(io, "Truncated %zu!=%zu", size_t(n), buf->size());
                impl->todo.pop_front();
                return;
            }

            impl->todo.pop_front();
        }

    }catch(std::exception& e){
        log_exc_printf(setup, "Unhandled nl error in %s : %s\n", __func__, e.what());
    }
}

void NLSocket::Impl::onRX(int, short, void *raw)
{
    auto self(static_cast<NLSocket*>(raw));
    auto impl(self->impl.get());
    try{
        for(unsigned i=0; i<10; i++) { // limit number of replies before reschedule
            sockaddr_nl addr;
            socklen_t alen = sizeof(addr);
            auto buf(std::make_shared<std::vector<char>>(impl->maxrx));

            auto n = recvfrom(impl->sock.sock, buf->data(), buf->size(), 0,
                              reinterpret_cast<sockaddr*>(&addr), &alen);

            if(n<0) {
                auto err = SOCKERRNO;
                if(err==EWOULDBLOCK || err==EAGAIN) {
                    return; // try again later
                }
                // treat as unrecoverable...
                if(event_del(impl->evt_rx.get()))
                    log_warn_printf(io, "Unable to disable evt_rx%s", "\n");
                log_err_printf(io, "recvfrom() Error %d\n", err);
                return;

            } else if(n<NLMSG_HDRLEN) {
                log_warn_printf(io, "Truncated NLMSG %zd\n", n);
                continue;
            }

            auto hdr = reinterpret_cast<const nlmsghdr*>(buf->data());
            size_t remaining = n;

            for(; NLMSG_OK(hdr, remaining); hdr = NLMSG_NEXT(hdr, remaining)) {
                if(hdr->nlmsg_pid==impl->mypid) {
                    auto it(impl->requests.find(hdr->nlmsg_seq));
                    if(it!=impl->requests.end()) {
                        if(auto req = it->second.lock()) {
                            std::shared_ptr<const nlmsghdr> msg(buf, hdr); // alias
                            try{
                                req->handler(msg);
                            }catch(std::exception& e){
                                log_err_printf(io, "Unhandled exception from NL Request handler %s : %s\n",
                                               req->handler.target_type().name(), e.what());
                                impl->requests.erase(req->seq);
                            }
                        }
                    } else {
                        log_warn_printf(io, "Orphaned reply seq=%u\n", unsigned(hdr->nlmsg_seq));
                    }
                }
            }

            if(remaining)
                log_warn_printf(io, "NLMSG trailing junk %zd/%zu\n", n, remaining);
        }

    }catch(std::exception& e){
        log_exc_printf(setup, "Unhandled nl error in %s : %s\n", __func__, e.what());
    }
}

const Response &Reply::reply()
{
    throw std::logic_error("Not implemented");
}

AttrIter Response::_check_blen(size_t blen) const
{
    // length of header and body (up to first attribute)
    auto hlen = NLMSG_LENGTH(blen);  // excluding trailing pad
    auto hspace = NLMSG_SPACE(blen); // including trailing pad
    // assert(hspace >= hlen);

    if(msg->nlmsg_len < hlen)
        throw std::logic_error("Response body insufficient for expected payload");

    auto base = reinterpret_cast<const char*>(msg.get());
    return AttrIter{base+hspace, msg->nlmsg_len-hspace};
}

}} // namespace pvxs::nl
