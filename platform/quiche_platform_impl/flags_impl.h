#pragma once

// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"

namespace quiche {

class Flag;

// TODO: modify flags implementation to be backed by
// Runtime::runtimeFeatureEnabled(), which is the canonical QUICHE way of
// enabling and disabling features.

// Registry of QUICHE flags. Can be used to reset all flags to default values,
// and to look up and set flags by name.
class FlagRegistry {
public:
  ~FlagRegistry() = default;

  // Return singleton instance.
  static FlagRegistry& GetInstance();

  // Reset all registered flags to their default values.
  void ResetFlags() const;

  // Look up a flag by name.
  Flag* FindFlag(const std::string& name) const;

  void AddFlag(const std::string& name, Flag* f);
  void RemoveFlag(const std::string& name);

  absl::flat_hash_map<std::string, Flag*> FilterFlagsByLocation(const std::string& loc);

private:
  FlagRegistry();

  absl::flat_hash_map<std::string, Flag*> flags_;
};

// Abstract class for QUICHE protocol and feature flags.
class Flag {
public:
  // Construct Flag with the given name and help string.
  Flag(const char* name, const char* loc, const char* help)
    : name_(name), loc_(loc), help_(help) {
  }
  virtual ~Flag() = default;

  // Set flag value from given string, returning true iff successful.
  virtual bool SetValueFromString(const std::string& value_str) = 0;

  // Reset flag to default value.
  virtual void ResetValue() = 0;

  // Return flag name.
  std::string name() const { return name_; }

  std::string location() const { return loc_; }

  // Return flag help string.
  std::string help() const { return help_; }

private:
  std::string name_;
  std::string loc_;
  std::string help_;
};

// Concrete class for QUICHE protocol and feature flags, templated by flag type.
template <typename T> class TypedFlag : public Flag {
public:
  TypedFlag(const char* name, const char* loc, T default_value, const char* help)
      : Flag(name, loc, help), value_(default_value), default_value_(default_value) {
    FlagRegistry::GetInstance().AddFlag(Flag::name(), this);
  }

  virtual ~TypedFlag() {
    FlagRegistry::GetInstance().RemoveFlag(Flag::name());
  }

  bool SetValueFromString(const std::string& value_str) override;

  void ResetValue() override {
    absl::MutexLock lock(&mutex_);
    value_ = default_value_;
  }

  // Set flag value.
  void SetValue(T value) {
    absl::MutexLock lock(&mutex_);
    value_ = value;
  }

  // Return flag value.
  T value() const {
    absl::MutexLock lock(&mutex_);
    return value_;
  }

private:
  mutable absl::Mutex mutex_;
  T value_ ABSL_GUARDED_BY(mutex_);
  T default_value_;
};

// SetValueFromString specializations
template <> bool TypedFlag<bool>::SetValueFromString(const std::string& value_str);
template <> bool TypedFlag<int32_t>::SetValueFromString(const std::string& value_str);
template <> bool TypedFlag<int64_t>::SetValueFromString(const std::string& value_str);
template <> bool TypedFlag<uint64_t>::SetValueFromString(const std::string& value_str);
template <> bool TypedFlag<double>::SetValueFromString(const std::string& value_str);
template <> bool TypedFlag<std::string>::SetValueFromString(const std::string& value_str);

} // namespace quiche

// QuicFlag declarations
#define QUIC_FLAG(flag, value) extern bool flag;
#include "gquiche/quic/core/quic_flags_list.h"
#undef QUIC_FLAG

// QuicProtocolFlag declarations
#define QUIC_PROTOCOL_FLAG(type, flag, value, help) extern quiche::TypedFlag<type>* FLAGS_##flag;
#include "gquiche/quic/core/quic_protocol_flags_list.h"
#undef QUIC_PROTOCOL_FLAG

