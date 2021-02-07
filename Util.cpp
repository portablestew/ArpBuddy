// arpbuddy - copyright 2021
#include <Util.h>

namespace Util
{
    namespace
    {
        const char *const g_nibbleToHex = "0123456789abcdef";
    }

    void PrintHardwareAddr(std::ostream &os, const std::uint8_t addr[6])
    {
        os << g_nibbleToHex[(addr[0] >> 4) & 0xf] << g_nibbleToHex[addr[0] & 0xf] << ':';
        os << g_nibbleToHex[(addr[1] >> 4) & 0xf] << g_nibbleToHex[addr[1] & 0xf] << ':';
        os << g_nibbleToHex[(addr[2] >> 4) & 0xf] << g_nibbleToHex[addr[2] & 0xf] << ':';
        os << g_nibbleToHex[(addr[3] >> 4) & 0xf] << g_nibbleToHex[addr[3] & 0xf] << ':';
        os << g_nibbleToHex[(addr[4] >> 4) & 0xf] << g_nibbleToHex[addr[4] & 0xf] << ':';
        os << g_nibbleToHex[(addr[5] >> 4) & 0xf] << g_nibbleToHex[addr[5] & 0xf];
    }

    void PrintProtocolAddr(std::ostream &os, const std::uint8_t addr[4])
    {
        os << int(addr[0]) << '.';
        os << int(addr[1]) << '.';
        os << int(addr[2]) << '.';
        os << int(addr[3]);
    }
} // namespace Util
