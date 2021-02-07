// arpbuddy - copyright 2021
#pragma once

#include <ArpSocket.h>

#include <map>
#include <string>

// Wrapper for ARP buddy functionality
// - Snooping for repetitive ARP requests
// - Spoofing a reply directly to the requester
class ArpBuddy
{
public:
    struct Config
    {
        const char *ifaceName = nullptr; // Ethernet interface
        int verbosity = 0; // Log verbosity, larger is more verbose
        int numActionableRepeats = 3; // How many repeated requests before stepping in
    };

    ArpBuddy(const Config &config);

    // Returns true if initialization was successful.
    bool IsValid() const;

    // Perform the next operation. Repeat until returns false.
    bool Update();

private:
    struct RequestKey
    {
        RequestKey(const std::uint8_t srcHw[6], const std::uint8_t dstProto[4]);

        bool operator<(const RequestKey &rhs) const;

        // String concatenating requesting hardware address and requested proto
        static constexpr int KeyLen = 6 + 4;
        std::uint8_t m_srcHwDstProto[KeyLen];
    };

    void HandleRequest(const ArpSocket::ArpPacket &req);
    bool ResolveRequest(const ArpSocket::ArpPacket &req, ArpSocket::ArpPacket *outResp);

private:
    std::string m_ifaceName;
    int m_verbosity;
    int m_numActionableRepeats;

    ArpSocket m_sock;

    using RequestCountMap = std::map<RequestKey, int>;
    RequestCountMap m_requests;
};
