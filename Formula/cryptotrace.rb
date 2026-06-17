class Cryptotrace < Formula
  desc "Cryptographic fingerprinting and data classification engine"
  homepage "https://github.com/parv68/CryptoTrace"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/parv68/CryptoTrace/releases/download/v0.1.0/cryptotrace-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Placeholder
    else
      url "https://github.com/parv68/CryptoTrace/releases/download/v0.1.0/cryptotrace-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Placeholder
    end
  end

  on_linux do
    url "https://github.com/parv68/CryptoTrace/releases/download/v0.1.0/cryptotrace-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000" # Placeholder
  end

  def install
    bin.install "cryptotrace"
    bin.install "cryptotrace-worker"
    prefix.install "signatures"
    prefix.install "calibration_data"
    prefix.install "docs"
    prefix.install "cryptotrace.toml.example"
  end

  test do
    assert_match "CryptoTrace", shell_output("#{bin}/cryptotrace version")
  end
end
