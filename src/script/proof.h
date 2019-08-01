// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_PROOF_H
#define BITCOIN_SCRIPT_PROOF_H

#include <key.h>                    // CKey
#include <script/signingprovider.h> // SigningProvider
#include <script/standard.h>        // CTxDestination

namespace proof {

class privkey_unavailable_error : public std::runtime_error { public: explicit privkey_unavailable_error(const std::string& str = "Private key is not available") : std::runtime_error(str) {} };
class signing_error : public std::runtime_error { public: explicit signing_error(const std::string& str = "Sign failed") : std::runtime_error(str) {} };

/**
 * Attempt to sign a message with the given destination.
 */
void SignMessageWithSigningProvider(SigningProvider* sp, const std::string& message, const CTxDestination& destination, std::vector<uint8_t>& signature_out);

/**
 * Attempt to sign a message with the given private key.
 */
void SignMessageWithPrivateKey(CKey& key, const std::string& message, std::vector<uint8_t>& signature_out);

/**
 * Determine if a signature is valid for the given message.
 */
bool VerifySignature(const std::string& message, const CTxDestination& destination, const std::vector<uint8_t>& signature);

} // namespace proof

#endif // BITCOIN_SCRIPT_PROOF_H
