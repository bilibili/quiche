#pragma once

// NOLINT(namespace-quiche)

// This file is part of the QUICHE platform implementation, and is not to be
// consumed or referenced directly by other QUICHE code. It serves purely as a
// porting layer for QUICHE.

#include <string>
#include <vector>
#include <iostream>

#include "platform/quiche_platform_impl/flags_impl.h"
#include "absl/strings/str_split.h"

// |flag| is the global flag variable, which is a pointer to TypedFlag<type>.
#define GetQuicheFlagImpl(flag)                          (flag)->value()
// |flag| is the global flag variable, which is a pointer to TypedFlag<type>.
#define SetQuicheFlagImpl(flag, value)                   (flag)->SetValue(value)
#define GetQuicheReloadableFlagImpl(module, flag)        FLAGS_quic_reloadable_flag_##flag
#define SetQuicheReloadableFlagImpl(module, flag, value) ((FLAGS_quic_reloadable_flag_##flag) = (value))
#define GetQuicheRestartFlagImpl(module, flag)           FLAGS_quic_restart_flag_##flag
#define SetQuicheRestartFlagImpl(module, flag, value)    (FLAGS_quic_restart_flag_##flag) = (value))

// Not wired into command-line parsing.
#define DEFINE_QUIC_COMMAND_LINE_FLAG_IMPL(type, flag, value, help)                     \
    quiche::TypedFlag<type>* FLAGS_##flag = new quiche::TypedFlag<type>(#flag, "cmdline", value, help);

namespace quiche {

// TODO(mpwarres): implement. Lower priority since only used by QUIC command-line tools.
inline std::vector<std::string> QuicParseCommandLineFlagsImpl(
    const char* usage,
    int argc,
    const char* const* argv) {

    std::vector<std::string> params;

    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            std::vector<std::string> fv_strs = absl::StrSplit(std::string(argv[i] + 2), '=');
            if (fv_strs.empty()) {
                continue;
            }
            std::string flag_name  = fv_strs[0];
            std::string flag_value = fv_strs.size() > 1 ? fv_strs[1] : "";
            auto flag_ptr = quiche::FlagRegistry::GetInstance().FindFlag(flag_name);
            if (flag_ptr == nullptr) {
                std::cout << "Invalid flag of " << fv_strs[0] << std::endl;
                return {};
            }
            flag_ptr->SetValueFromString(flag_value);
            continue;
        }

        params.push_back(std::string(argv[i]));
    }

  return params;
}

// TODO(mpwarres): implement. Lower priority since only used by QUIC command-line tools.
inline void QuicPrintCommandLineFlagHelpImpl(const char* usage) {

    std::cout << std::string(usage) << std::endl;

    auto cmdline_flags = quiche::FlagRegistry::GetInstance().FilterFlagsByLocation("cmdline");
    for (const auto& kv : cmdline_flags) {
        std::cout << "--" << kv.first << "\t\t" << kv.second->help() << std::endl;
    }
}

} // namespace quiche

namespace quic {

    inline std::vector<std::string> QuicParseCommandLineFlagsImpl(
        const char* usage,
        int argc,
        const char* const* argv) {
        return quiche::QuicParseCommandLineFlagsImpl(usage, argc, argv);
    }

    inline void QuicPrintCommandLineFlagHelpImpl(const char* usage) {
        return quiche::QuicPrintCommandLineFlagHelpImpl(usage);
    }
}
