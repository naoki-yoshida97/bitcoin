// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/proof.h>

const std::string strMessageMagic = "Bitcoin Signed Message:\n";

namespace proof
{

void SignMessageWithSigningProvider(SigningProvider* sp, const std::string& message, const CTxDestination& destination, std::vector<uint8_t>& signature_out)
{
    signature_out.clear();

    const PKHash *pkhash = boost::get<PKHash>(&destination);
    if (pkhash) {
        CKey key;
        if (!sp->GetKey(CKeyID(*pkhash), key)) {
            throw privkey_unavailable_error();
        }

        CHashWriter ss(SER_GETHASH, 0);
        ss << strMessageMagic << message;

        if (!key.SignCompact(ss.GetHash(), signature_out)) {
            throw signing_error();
        }
    } else {
        throw signing_error("unable to sign with non-p2pkh addresses");
    }
}

void SignMessageWithPrivateKey(CKey& key, const std::string& message, std::vector<uint8_t>& signature_out)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << message;

    if (!key.SignCompact(ss.GetHash(), signature_out)) {
        throw signing_error();
    }
}

bool VerifySignature(const std::string& message, const CTxDestination& destination, const std::vector<uint8_t>& signature)
{
    const PKHash* pkhash = boost::get<PKHash>(&destination);
    if (pkhash) {
        CHashWriter ss(SER_GETHASH, 0);
        ss << strMessageMagic << message;
        CPubKey pubkey;
        return pubkey.RecoverCompact(ss.GetHash(), signature) && pubkey.GetID() == *pkhash;
    }

    throw signing_error("unable to verify non-p2pkh address messages");
}

}
