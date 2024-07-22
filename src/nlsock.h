/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef NLSOCK_H
#define NLSOCK_H

#include <stdexcept>
#include <functional>
#include <memory>
#include <map>

#include <string.h>
#include <arpa/inet.h>

#include <linux/netlink.h>

#include <pvxs/version.h>

namespace pvxs {namespace nl {

template<typename T>
struct bswap {};
template<>
struct bswap<uint8_t> { static inline uint8_t ntoh(uint8_t v) { return v; }};
template<>
struct bswap<uint16_t> { static inline uint16_t ntoh(uint16_t v) { return ntohs(v); }};
template<>
struct bswap<uint32_t> { static inline uint32_t ntoh(uint32_t v) { return ntohl(v); }};

using RemoteError = std::runtime_error;

struct NLSocket;
struct Attr;

struct AttrIter {
    using value_type = Attr;

    PVXS_API
    value_type next();

    constexpr
    AttrIter(const void *cur, size_t remaining)
        :cur(cur)
        ,remaining(remaining)
    {}
private:
    const void *cur;
    size_t remaining;
};

struct Attr {
    const nlattr *attr = nullptr;

    Attr() = default;
    constexpr inline
    Attr(const nlattr *attr) :attr(attr) {}

    explicit operator bool() const {
        return attr;
    }

    inline constexpr
    bool is_nested() const {
        return attr->nla_type&NLA_F_NESTED;
    }
    inline constexpr
    uint16_t mtype() const {
        return attr->nla_type&NLA_TYPE_MASK;
    }
    inline constexpr
    size_t size() const {
        return attr->nla_len - NLA_HDRLEN;
    }
    inline constexpr
    const void* data() const {
        return NLA_HDRLEN+(const char*)(const void*)attr;
    }
    template<typename V, bool be=false>
    V as() const {
        if(size()<sizeof(V))
            throw std::runtime_error("nlattr too small");
        union {
            V v;
            char c[sizeof(V)];
        } pun;
        memcpy(pun.c, data(), sizeof(pun.c));
        if(be)
            return bswap<V>::ntoh(pun.v);
        else
            return pun.v;
    }

    inline
    AttrIter nested() const {
        return AttrIter{data(), size()};
    }
};

struct Response {
    inline constexpr
    uint16_t mtype() const {
        return msg->nlmsg_type;
    }
    inline constexpr
    uint16_t mflags() const {
        return msg->nlmsg_flags;
    }

    template<typename B>
    std::pair<const B&, AttrIter> split_as() const {
        const size_t blen = sizeof(B);
        auto at= _check_blen(blen);
        const B& b = *reinterpret_cast<const B*>(msg.get() + NLMSG_HDRLEN);
        return std::make_pair(b, std::move(at));
    }

    Response(const std::shared_ptr<const nlmsghdr>& msg)
        :msg(msg)
    {}
private:
    std::shared_ptr<const nlmsghdr> msg;
    PVXS_API
    AttrIter _check_blen(size_t blen) const;
};

struct Reply {
    //! access response message
    //! @throws RemoteError if is_last() and err()!=0
    PVXS_API
    const Response& reply();

    bool valid() const {
        return msg.operator bool();
    }
    explicit operator bool() const {
        return msg.operator bool();
    }

    inline
    uint16_t mtype() const {
        return msg->nlmsg_type;
    }
    inline
    uint16_t mflags() const {
        return msg->nlmsg_flags;
    }

    inline
    bool is_last() const {
        return msg->nlmsg_type==NLMSG_ERROR || msg->nlmsg_type==NLMSG_DONE;
    }
    //! DONE or ERROR with code==0
    bool is_ok() const {
        if(msg->nlmsg_type==NLMSG_DONE) {
            return true;
        } else if(msg->nlmsg_type==NLMSG_ERROR) {
            auto err(reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(msg.get())));
            return err->error==0;
        } else {
            return false;
        }
    }
    //! if ERROR , return code.  others return 0.
    int err() const;

    Reply() = default;
    Reply(const std::shared_ptr<const nlmsghdr>& msg)
        :msg(msg)
    {}
private:
    std::shared_ptr<const nlmsghdr> msg;
    friend struct NLSocket;
};

struct PVXS_API Request {
    struct Impl;

    ~Request();
    void cancel();

private:
    std::shared_ptr<Impl> impl;
    friend struct NLSocket;
};

struct PVXS_API NLSocket {
    NLSocket() = default;
    explicit NLSocket(int proto);
    ~NLSocket();

    /** Send the (modified) message and route any replies.
     *
     * @param msg Request message.  callee will queue a copy.
     * @param cb  Replies for this sequence number will be delivered through this callable.
     */
    Request request(const nlmsghdr& msg,
                    std::function<void(Reply&&)>&& cb);

    /** Send request w/ ACK, and await a DONE message.
     * @param msg
     * @return
     */
    void request_ack(const nlmsghdr& msg, double timeout = -1);

    /** Listen for multicast messages.
     *
     * callback is expected to ignore unexpected messages
     */
    Request listen(std::function<void(Reply&&)>&&);

    struct Impl;
private:
    std::shared_ptr<Impl> impl;
};

}} // namespace pvxs::nl

#endif // NLSOCK_H
