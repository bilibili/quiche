// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include "platform/quiche_platform_impl/flags_impl.h"

#include <set>

#include "absl/strings/ascii.h"
#include "absl/strings/numbers.h"


namespace quiche {

// static
FlagRegistry& FlagRegistry::GetInstance() {
  static auto* instance = new FlagRegistry();
  return *instance;
}

FlagRegistry::FlagRegistry() {
}

void FlagRegistry::ResetFlags() const {
  for (auto& kv : flags_) {
    kv.second->ResetValue();
  }
}

Flag* FlagRegistry::FindFlag(const std::string& name) const {
  auto it = flags_.find(name);
  return (it != flags_.end()) ? it->second : nullptr;
}

void FlagRegistry::AddFlag(const std::string& name, Flag* f) {
  flags_.emplace(name, f);
}

void FlagRegistry::RemoveFlag(const std::string& name)
{
  flags_.erase(name);
}

absl::flat_hash_map<std::string, Flag*> FlagRegistry::FilterFlagsByLocation(const std::string& loc) {

  absl::flat_hash_map<std::string, Flag*> filter_flags;
  for (const auto& kv : flags_) {
    if (kv.second->location() != loc) continue;
    filter_flags.emplace(kv.first, kv.second);
  }

  return filter_flags;
}

template <> bool TypedFlag<bool>::SetValueFromString(const std::string& value_str) {
  static const auto* kTrueValues = new std::set<std::string>({"1", "t", "true", "y", "yes"});
  static const auto* kFalseValues = new std::set<std::string>({"0", "f", "false", "n", "no"});
  auto lower = absl::AsciiStrToLower(value_str);
  if (kTrueValues->find(lower) != kTrueValues->end()) {
    SetValue(true);
    return true;
  }
  if (kFalseValues->find(lower) != kFalseValues->end()) {
    SetValue(false);
    return true;
  }
  return false;
}

template <> bool TypedFlag<int32_t>::SetValueFromString(const std::string& value_str) {
  int32_t value;
  if (absl::SimpleAtoi(value_str, &value)) {
    SetValue(value);
    return true;
  }
  return false;
}

template <> bool TypedFlag<int64_t>::SetValueFromString(const std::string& value_str) {
  int64_t value;
  if (absl::SimpleAtoi(value_str, &value)) {
    SetValue(value);
    return true;
  }
  return false;
}

template <> bool TypedFlag<uint64_t>::SetValueFromString(const std::string& value_str) {
  uint64_t value;
  if (absl::SimpleAtoi(value_str, &value)) {
    SetValue(value);
    return true;
  }
  return false;
}

template <> bool TypedFlag<double>::SetValueFromString(const std::string& value_str) {
  double value;
  if (absl::SimpleAtod(value_str, &value)) {
    SetValue(value);
    return true;
  }
  return false;
}

template <> bool TypedFlag<std::string>::SetValueFromString(const std::string& value_str) {
  SetValue(value_str);
  return true;
}

} // namespace quiche

// QuicFlag definitions
#define QUIC_FLAG(flag, value) bool flag = value;
#include "gquiche/quic/core/quic_flags_list.h"
#undef QUIC_FLAG

// QuicProtocolFlag definitions
#define QUIC_PROTOCOL_FLAG(type, flag, value, help) quiche::TypedFlag<type>* FLAGS_##flag = new quiche::TypedFlag<type>(#flag, "quiche", value, help);
#include "gquiche/quic/core/quic_protocol_flags_list.h"
#undef QUIC_PROTOCOL_FLAG
