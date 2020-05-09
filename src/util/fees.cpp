// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/fees.h>

#include <policy/fees.h>
#include <util/strencodings.h>

#include <map>
#include <string>
#include <vector>
#include <utility>

std::string StringForFeeReason(FeeReason reason)
{
    static const std::map<FeeReason, std::string> fee_reason_strings = {
        {FeeReason::NONE, "None"},
        {FeeReason::HALF_ESTIMATE, "Half Target 60% Threshold"},
        {FeeReason::FULL_ESTIMATE, "Target 85% Threshold"},
        {FeeReason::DOUBLE_ESTIMATE, "Double Target 95% Threshold"},
        {FeeReason::CONSERVATIVE, "Conservative Double Target longer horizon"},
        {FeeReason::MEMPOOL_MIN, "Mempool Min Fee"},
        {FeeReason::PAYTXFEE, "PayTxFee set"},
        {FeeReason::FALLBACK, "Fallback fee"},
        {FeeReason::REQUIRED, "Minimum Required Fee"},
    };
    auto reason_string = fee_reason_strings.find(reason);

    if (reason_string == fee_reason_strings.end()) return "Unknown";

    return reason_string->second;
}

static const std::vector<std::pair<std::string, FeeEstimateMode>> FEE_MODES = {
    {"unset", FeeEstimateMode::UNSET},
    {"economical", FeeEstimateMode::ECONOMICAL},
    {"conservative", FeeEstimateMode::CONSERVATIVE},
};

std::string FeeModes(const std::string& delimiter)
{
    std::string r;
    std::string prefix = "";
    for (const auto& pair : FEE_MODES) {
        r += prefix + pair.first;
        prefix = delimiter;
    }
    return r;
}

bool FeeModeFromString(const std::string& mode_string, FeeEstimateMode& fee_estimate_mode)
{
    auto searchkey = ToUpper(mode_string);
    for (const auto& pair : FEE_MODES) {
        if (ToUpper(pair.first) == searchkey) {
            fee_estimate_mode = pair.second;
            return true;
        }
    }
    return false;
}
