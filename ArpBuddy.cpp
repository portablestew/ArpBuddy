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
        switch (static_cast<ArpSocket::Operation>(packet->m_operation))
        {
        case ArpSocket::Operation::Request:
            HandleRequest(*packet);
            break;

        case ArpSocket::Operation::Response:
            break;
        }
    }

    return true;
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
    std::memcpy((char *)outResp->m_srcProtoAddr, (const char *)req.m_dstProtoAddr, 4);
    std::memcpy((char *)outResp->m_dstHardwareAddr, (const char *)req.m_srcHardwareAddr, 6);
    std::memcpy((char *)outResp->m_dstProtoAddr, (const char *)req.m_srcProtoAddr, 4);

    bool isResolved = false;

    // Try a local ARP query
    if (m_sock.ResolveProto(req.m_dstProtoAddr, outResp->m_srcHardwareAddr))
    {
        isResolved = true;
    }

    // TODO: try additional methods to resolve the address
    // - Local interfaces
    // - Snooped from any other ARP packet
    // - DHCP cache, if available
    // - Live, actual ARP request?

    return isResolved;
}

ArpBuddy::RequestKey::RequestKey(const std::uint8_t srcHw[6], const std::uint8_t dstProto[4])
{
    std::strncmp((const char *)m_srcHwDstProto, (const char *)srcHw, 6);
    std::strncmp((const char *)m_srcHwDstProto + 6, (const char *)srcHw, 4);
}

bool ArpBuddy::RequestKey::operator<(const RequestKey &rhs) const
{
    return std::strncmp((const char *)m_srcHwDstProto, (const char *)rhs.m_srcHwDstProto, KeyLen) < 0;
}
