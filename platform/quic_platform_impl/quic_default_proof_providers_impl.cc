#include "platform/quic_platform_impl/quic_default_proof_providers_impl.h"
#include "gquiche/quic/core/crypto/proof_source_x509.h"
#include "base/files/file_util.h"
#include "gquiche/common/platform/api/quiche_command_line_flags.h"
#include "gquiche/common/platform/api/quiche_reference_counted.h"
#include <utility>

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string,
                              certificate_file,
                              "",
                              "Path to the certificate chain.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string,
                              key_file,
                              "",
                              "Path to the pkcs8 private key.");

namespace quic {

std::unique_ptr<ProofVerifier> CreateDefaultProofVerifierImpl(
    const std::string& host) {
  // TODO implement
  return nullptr;
}

std::unique_ptr<ProofSource> CreateDefaultProofSourceImpl() {

  const base::FilePath cert_path = base::FilePath(GetQuicFlag(FLAGS_certificate_file));
  const base::FilePath key_path  = base::FilePath(GetQuicFlag(FLAGS_key_file));

  if (!cert_path.IsAbsolute() || !key_path.IsAbsolute()) {
    QUIC_DLOG(FATAL) << "Certificate and key paths must be absolute.";
    return nullptr;
  }

  // Initialize OpenSSL if it isn't already initialized. This must be called
  // before any other OpenSSL functions though it is safe and cheap to call this
  // multiple times.
  // This function is thread-safe, and OpenSSL will only ever be initialized once.
  // OpenSSL will be properly shut down on program exit.
  // CRYPTO_library_init may be safely called concurrently.
  CRYPTO_library_init();

  std::string cert_data;
  if (!base::ReadFileToString(cert_path, &cert_data)) {
    QUIC_DLOG(FATAL) << "Unable to read certificates.";
    return nullptr;
  }

  std::stringstream cert_stream(cert_data);
  std::vector<std::string> certs = CertificateView::LoadPemFromStream(&cert_stream);

  auto default_chain = quiche::QuicheReferenceCountedPointer<ProofSource::Chain>(new ProofSource::Chain(certs));

  std::string key_data;
  if (!base::ReadFileToString(key_path, &key_data)) {
    QUIC_DLOG(FATAL) << "Unable to read key.";
    return nullptr;
  }
  std::unique_ptr<CertificatePrivateKey> default_key = CertificatePrivateKey::LoadFromDer(key_data);
  if (default_key == nullptr) {
    QUIC_DLOG(FATAL) << "default key is null.";
    return nullptr;
  }

  std::unique_ptr<ProofSourceX509> proof_source_x509 = ProofSourceX509::Create(default_chain, std::move(*default_key));
  std::unique_ptr<ProofSource> proof_source(proof_source_x509.release());

  return std::move(proof_source);
}

}  // namespace quic
