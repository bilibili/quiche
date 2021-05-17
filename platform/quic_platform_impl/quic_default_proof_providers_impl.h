#pragma once

#include <memory>

#include "gquiche/quic/core/crypto/proof_source.h"
#include "gquiche/quic/core/crypto/proof_verifier.h"

namespace quic {

std::unique_ptr<ProofVerifier> CreateDefaultProofVerifierImpl(
    const std::string& host);
std::unique_ptr<ProofSource> CreateDefaultProofSourceImpl();

}  // namespace quic
