// arpbuddy - copyright 2021
#include <ArpSocket.h>

#include <Util.h>

#include <net/if.h>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

// Note: Largely based off of samples like https://hundeboll.net/receiving-udp-packets-in-promiscuous-mode.html

ArpSocket::ArpSocket(const char *ifaceName)
    : m_ifaceName(ifaceName)
{
    static const sock_filter s_arpFilter[] = {
        // sudo tcpdump -dd arp
        {0x28, 0, 0, 0x0000000c},
        {0x15, 0, 1, 0x00000806},
        {0x6, 0, 0, 0x00040000},
        {0x6, 0, 0, 0x00000000},
    };

    // Open socket for ethernet packets
    m_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_sock < 0)
    {
        std::cerr << "[ERROR] ArpSocket failure: socket() not valid" << std::endl;
        return;
    }

    // Apply socket filter
    sock_fprog sfp = {0};
    sfp.len = sizeof(s_arpFilter) / sizeof(sock_filter);
    sfp.filter = const_cast<sock_filter *>(s_arpFilter);

    if (setsockopt(m_sock, SOL_SOCKET, SO_ATTACH_FILTER, &sfp, sizeof(sfp)) != 0)
    {
        std::cerr << "[ERROR] ArpSocket failure: could not attach filter" << std::endl;
        return;
    }

    // Locate some interface properties
    ifreq ifaceIfr = {0};
    std::strncpy(ifaceIfr.ifr_name, ifaceName, IF_NAMESIZE);
    if (ioctl(m_sock, SIOCGIFINDEX, &ifaceIfr) != 0 || ifaceIfr.ifr_ifindex < 0)
    {
        std::cerr << "[ERROR] ArpSocket failure: could not get iface index for " << ifaceName << std::endl;
        return;
    }
    m_ifaceIdx = ifaceIfr.ifr_ifindex;

    if (ioctl(m_sock, SIOCGIFHWADDR, &ifaceIfr) != 0)
    {
        std::cerr << "[ERROR] ArpSocket failure: could not get iface hwaddr" << std::endl;
        return;
    }
    std::memcpy(m_ifaceHwAddr, ifaceIfr.ifr_addr.sa_data, ETH_ALEN);

    // Set the interface to promiscuous
    if (!SetPacketOption(PACKET_MR_PROMISC, PACKET_ADD_MEMBERSHIP))
    {
        std::cerr << "[ERROR] ArpSocket failure: promiscuous membership denied" << std::endl;
        return;
    }

    // Bind them together
    sockaddr_ll sa = {0};
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = m_ifaceIdx;
    sa.sll_protocol = htons(ETH_P_ALL);
    if (bind(m_sock, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0)
    {
        std::cerr << "[ERROR] ArpSocket failure: bind() error" << std::endl;
        return;
    }

    //std::cerr << "ArpSocket " << m_sock << " bound promiscuous with " << ifaceName << "=" << m_ifaceIdx << std::endl;
    m_isValid = true;
}

ArpSocket::~ArpSocket()
{
    if (m_sock >= 0)
    {
        SetPacketOption(PACKET_MR_PROMISC, PACKET_DROP_MEMBERSHIP);
        close(m_sock);
    }
}

bool ArpSocket::IsValid() const
{
    return m_isValid;
}

const ArpSocket::ArpPacket *ArpSocket::RecvNext(unsigned char buf[ArpBufferSize])
{
    ArpPacket *arp = nullptr;

    while (m_sock >= 0)
    {
        int bytes = RecvRaw(buf, ArpBufferSize);
        if (bytes <= 0)
        {
            break;
        }

        // Drop malformed packets
        if (bytes < ArpBufferSize)
        {
            continue;
        }

        arp = reinterpret_cast<ArpPacket *>(buf + EthernetSize);
        arp->m_hardwareType = ntohs(arp->m_hardwareType);
        arp->m_protocolType = ntohs(arp->m_protocolType);
        arp->m_operation = ntohs(arp->m_operation);

        // Drop malformed packets
        if (arp->m_hardwareType != 1 || arp->m_protocolType != 0x0800 ||
            arp->m_hardwareLen != 6 || arp->m_protocolLen != 4 ||
            arp->m_operation < 1 || arp->m_operation > 2)
        {
            continue;
        }

        break;
    }

    return arp;
}

bool ArpSocket::IsLocalInterfaceInvolved(const ArpPacket &packet) const
{
    return std::memcmp(m_ifaceHwAddr, packet.m_srcHardwareAddr, ETH_ALEN) == 0 ||
           std::memcmp(m_ifaceHwAddr, packet.m_dstHardwareAddr, ETH_ALEN) == 0;
}

bool ArpSocket::SpoofResponse(const ArpPacket &packet)
{
    if (m_sock < 0)
    {
        return false;
    }

    unsigned char buf[ArpBufferSize];

    // Set an ethernet header using the packet's addresses
    ethhdr *eth = reinterpret_cast<ethhdr *>(buf);
    std::memcpy(eth->h_dest, packet.m_dstHardwareAddr, ETH_ALEN);
    std::memcpy(eth->h_source, packet.m_srcHardwareAddr, ETH_ALEN);
    eth->h_proto = htons(0x0806);

    // Don't forget the ARP payload
    ArpPacket *payload = reinterpret_cast<ArpPacket *>(buf + EthernetSize);
    *payload = packet;
    payload->m_hardwareType = htons(payload->m_hardwareType);
    payload->m_protocolType = htons(payload->m_protocolType);
    payload->m_operation = htons(payload->m_operation);

    sockaddr_ll addr;
    addr.sll_ifindex = m_ifaceIdx;
    addr.sll_halen = ETH_ALEN;
    std::memcpy(addr.sll_addr, packet.m_dstHardwareAddr, ETH_ALEN);

    int bytes = sendto(m_sock, buf, ArpBufferSize, 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    return bytes == ArpBufferSize;
}

bool ArpSocket::ResolveProto(const std::uint8_t proto[4], std::uint8_t outHardware[6]) const
{
    arpreq garp = {0};
    sockaddr_in &targetAddr = reinterpret_cast<sockaddr_in &>(garp.arp_pa);
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr.s_addr = *reinterpret_cast<const in_addr_t *>(proto);
    std::strcpy(garp.arp_dev, m_ifaceName.c_str());

    if (ioctl(m_sock, SIOCGARP, &garp) == 0)
    {
        std::memcpy((char *)outHardware, garp.arp_ha.sa_data, ETH_ALEN);
        return true;
    }

    return false;
}

bool ArpSocket::SetPacketOption(int type, int optname)
{
    if (m_ifaceIdx < 0)
    {
        return false;
    }

    packet_mreq pmr = {0};
    pmr.mr_ifindex = m_ifaceIdx;
    pmr.mr_type = type;

    return setsockopt(m_sock, SOL_PACKET, optname, &pmr, sizeof(pmr)) == 0;
}

int ArpSocket::RecvRaw(unsigned char *buf, int bufSize)
{
    if (m_sock < 0)
    {
        return -1;
    }

    return recvfrom(m_sock, buf, bufSize, 0, nullptr, nullptr);
}

std::ostream &operator<<(std::ostream &os, const ArpSocket::ArpPacket &arp)
{
    os << "ht=" << arp.m_hardwareType << ", pt=" << arp.m_protocolType;
    os << ", hl=" << int(arp.m_hardwareLen) << ", pl=" << int(arp.m_protocolLen);
    os << ", op=" << arp.m_operation << ", src=";

    Util::PrintHardwareAddr(os, arp.m_srcHardwareAddr);
    os << '/';
    Util::PrintProtocolAddr(os, arp.m_srcProtoAddr);

    os << ", dst=";
    Util::PrintHardwareAddr(os, arp.m_dstHardwareAddr);
    os << '/';
    Util::PrintProtocolAddr(os, arp.m_dstProtoAddr);

    return os;
}
