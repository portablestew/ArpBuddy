// arpbuddy - copyright 2021
#pragma once

#include <cstdint>
#include <ostream>

// A socket for reading ARP packets
class ArpSocket
{
public:
    ArpSocket(const char *ifaceName);
    ~ArpSocket();

    bool IsValid() const;

    enum class Operation : std::uint16_t
    {
        Request = 1,
        Response = 2,
    };

    struct ArpPacket
    {
        std::uint16_t m_hardwareType;
        std::uint16_t m_protocolType;
        std::uint8_t m_hardwareLen;
        std::uint8_t m_protocolLen;
        std::uint16_t m_operation;
        std::uint8_t m_srcHardwareAddr[6];
        std::uint8_t m_srcProtoAddr[4];
        std::uint8_t m_dstHardwareAddr[6];
        std::uint8_t m_dstProtoAddr[4];
    } __attribute__((packed));

    static constexpr int EthernetSize = 14;
    static constexpr int ArpBufferSize = EthernetSize + sizeof(ArpPacket);

    // Receive the next ARP packet. Returned pointer refers to the passed in buffer memory.
    const ArpPacket *RecvNext(unsigned char buf[ArpBufferSize]);

    // Check if the packet involves this local host
    bool IsLocalInterfaceInvolved(const ArpPacket &packet) const;

    // Unicast a response packet
    bool SpoofResponse(const ArpPacket &packet);

    // Resolve an ARP request
    bool ResolveProto(const std::uint8_t proto[4], std::uint8_t outHardware[6]) const;

private:
    bool SetPacketOption(int type, int optname);
    int RecvRaw(unsigned char *buf, int bufSize);

    std::string m_ifaceName;
    int m_sock = -1;
    int m_ifaceIdx = -1;
    std::uint8_t m_ifaceHwAddr[6];

    bool m_isValid = false;
};

std::ostream &operator<<(std::ostream &os, const ArpSocket::ArpPacket &arp);
