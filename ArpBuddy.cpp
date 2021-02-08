// arpbuddy - copyright 2021
#include <ArpBuddy.h>

#include <Util.h>

#include <cstring>
#include <iostream>

ArpBuddy::ArpBuddy(const Config &config) : m_ifaceName(config.ifaceName),
                                           m_verbosity(config.verbosity),
                                           m_numActionableRepeats(config.numActionableRepeats),
                                           m_sock(config.ifaceName)
{
    if (m_sock.IsValid() && m_verbosity >= 1)
    {
        std::cerr << "ArpBuddy started, socket is valid." << std::endl;
    }
}

bool ArpBuddy::IsValid() const
{
    return m_sock.IsValid();
}

bool ArpBuddy::Update()
{
    unsigned char buf[ArpSocket::ArpBufferSize];
    if (const ArpSocket::ArpPacket *packet = m_sock.RecvNext(buf))
    {
        // Filter out packets to/from this local host
        if (m_sock.IsLocalInterfaceInvolved(*packet))
        {
            return true;
        }

        // Remember any addresses that come by
        CacheSnoopedAddresses(*packet);

        switch (static_cast<ArpSocket::Operation>(packet->m_operation))
        {
        case ArpSocket::Operation::Request:
            HandleRequest(*packet);
            break;

        case ArpSocket::Operation::Response:
            break;
        }

        return true;
    }

    return false;
}

void ArpBuddy::HandleRequest(const ArpSocket::ArpPacket &req)
{
    // When a request is repeated enough times, spoof a response
    RequestKey key(req.m_srcHardwareAddr, req.m_dstProtoAddr);
    int numSniffed = ++m_requests[key];

    if (m_verbosity >= 4)
    {
        std::cerr << "Sniff #" << numSniffed << ": " << req << std::endl;
    }

    if (numSniffed >= m_numActionableRepeats)
    {
        if (m_verbosity >= 3)
        {
            std::cerr << "Actionable: " << req << std::endl;
        }
        m_requests.erase(key);

        // Check if this local host has what they're looking for
        ArpSocket::ArpPacket response;
        if (ResolveRequest(req, &response))
        {
            // Send the response the requester is looking for
            if (m_sock.SpoofResponse(response))
            {
                if (m_verbosity >= 1)
                {
                    std::cerr << "Spoofed: " << response << std::endl;
                }
            }
            else
            {
                std::cerr << "[ERROR] SpoofResponse failed" << std::endl;
            }
        }
        else if (m_verbosity >= 2)
        {
            std::cerr << "Actionable, but not resolved: " << req << std::endl;
        }
    }
}

bool ArpBuddy::ResolveRequest(const ArpSocket::ArpPacket &req, ArpSocket::ArpPacket *outResp)
{
    *outResp = req;
    outResp->m_operation = static_cast<std::uint16_t>(ArpSocket::Operation::Response);
    std::memcpy((char *)outResp->m_srcProtoAddr, req.m_dstProtoAddr, 4);
    std::memcpy((char *)outResp->m_dstHardwareAddr, req.m_srcHardwareAddr, 6);
    std::memcpy((char *)outResp->m_dstProtoAddr, req.m_srcProtoAddr, 4);

    bool isResolved = false;

    // Try a local ARP query
    if (m_sock.ResolveProto(req.m_dstProtoAddr, outResp->m_srcHardwareAddr))
    {
        isResolved = true;

        if (m_verbosity <= 2)
        {
            std::cerr << "Resolved from local ARP." << std::endl;
        }
    }

    // Try a previously snooped address
    if (!isResolved)
    {
        auto cacheIt = m_cachedAddrs.find(ProtoAddrWrapper(req.m_dstProtoAddr));
        if (cacheIt != m_cachedAddrs.end())
        {
            std::memcpy(outResp->m_srcHardwareAddr, cacheIt->second.m_addr, sizeof(cacheIt->second.m_addr));
            isResolved = true;

            if (m_verbosity >= 2)
            {
                std::cerr << "Resolved from snooped address cache." << std::endl;
            }
        }
    }

    // TODO: try additional methods to resolve the address
    // - Local interfaces
    // - DHCP cache, if available
    // - Live, actual ARP request?

    return isResolved;
}

void ArpBuddy::CacheSnoopedAddresses(const ArpSocket::ArpPacket &packet)
{
    CacheSnoopedAddress(packet.m_srcHardwareAddr, packet.m_srcProtoAddr);
    CacheSnoopedAddress(packet.m_dstHardwareAddr, packet.m_dstProtoAddr);
}

void ArpBuddy::CacheSnoopedAddress(const std::uint8_t hardwareAddr[6], const std::uint8_t protoAddr[4])
{
    HardwareAddrWrapper hwa(hardwareAddr);
    ProtoAddrWrapper pta(protoAddr);

    if (!hwa.IsValid() || !pta.IsValid())
    {
        return;
    }

    if (m_cachedAddrs.count(pta) == 0 && m_verbosity >= 2)
    {
        std::cerr << "New snooped cache: ";
        Util::PrintProtocolAddr(std::cerr, pta.m_addr);
        std::cerr << " -> ";
        Util::PrintHardwareAddr(std::cerr, hwa.m_addr);
        std::cerr << std::endl;
    }

    m_cachedAddrs[pta] = hwa;
}

ArpBuddy::ProtoAddrWrapper::ProtoAddrWrapper()
{
    std::memset(m_addr, 0, sizeof(m_addr));
}

ArpBuddy::ProtoAddrWrapper::ProtoAddrWrapper(const std::uint8_t addr[4])
{
    std::memcpy(m_addr, addr, sizeof(m_addr));
}

bool ArpBuddy::ProtoAddrWrapper::IsValid() const
{
    static const std::uint8_t s_zeroes[] = {0, 0, 0, 0};
    static const std::uint8_t s_broascast[] = {0xff, 0xff, 0xff, 0xff};

    return std::memcmp(m_addr, s_zeroes, sizeof(m_addr)) != 0 &&
           std::memcmp(m_addr, s_broascast, sizeof(m_addr)) != 0;
}

bool ArpBuddy::ProtoAddrWrapper::operator<(const ProtoAddrWrapper &rhs) const
{
    return std::memcmp(m_addr, rhs.m_addr, sizeof(m_addr)) < 0;
}

ArpBuddy::HardwareAddrWrapper::HardwareAddrWrapper()
{
    std::memset(m_addr, 0, sizeof(m_addr));
}

ArpBuddy::HardwareAddrWrapper::HardwareAddrWrapper(const std::uint8_t addr[6])
{
    std::memcpy(m_addr, addr, sizeof(m_addr));
}

bool ArpBuddy::HardwareAddrWrapper::IsValid() const
{
    static const std::uint8_t s_zeroes[] = {0, 0, 0, 0, 0, 0};
    static const std::uint8_t s_broascast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    return std::memcmp(m_addr, s_zeroes, sizeof(m_addr)) != 0 &&
           std::memcmp(m_addr, s_broascast, sizeof(m_addr)) != 0;
}

ArpBuddy::RequestKey::RequestKey(const std::uint8_t srcHw[6], const std::uint8_t dstProto[4])
{
    std::memcpy(m_srcHwDstProto, srcHw, 6);
    std::memcpy(m_srcHwDstProto + 6, srcHw, 4);
}

bool ArpBuddy::RequestKey::operator<(const RequestKey &rhs) const
{
    return std::memcmp(m_srcHwDstProto, rhs.m_srcHwDstProto, KeyLen) < 0;
}
