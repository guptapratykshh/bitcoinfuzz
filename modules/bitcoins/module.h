#pragma once

#include <bitcoinfuzz/basemodule.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace bitcoinfuzz {
namespace module {

class BitcoinS : public BaseModule {
public:
  BitcoinS(void);

  // Generate a BIP-32 master private key from raw seed bytes and return its
  // Base58Check serialisation (the "xprv…" string).
  std::optional<std::string>
  bip32_master_keygen(std::span<const uint8_t> buffer) const override;

  // Parse a Base58Check-encoded extended key from the buffer and return
  // a normalised field string for differential comparison.
  std::optional<std::string> bip32_deserialize_extended_key(
      std::span<const uint8_t> buffer) const override;

  // Parse a raw PSBT (v0 / BIP-174) and return a summary string.
  std::optional<std::string>
  psbt_parse(std::span<const uint8_t> buffer) const override;

  ~BitcoinS() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
