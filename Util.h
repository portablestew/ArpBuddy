// arpbuddy - copyright 2021
#pragma once

#include <cstdint>
#include <ostream>

namespace Util
{
    void PrintHardwareAddr(std::ostream &os, const std::uint8_t addr[6]);
    void PrintProtocolAddr(std::ostream &os, const std::uint8_t addr[4]);
} // namespace Util
