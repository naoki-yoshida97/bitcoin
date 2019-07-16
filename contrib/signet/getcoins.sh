#!/usr/bin/env bash
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

#
# Get coins from Signet Faucet
#

faucet="https://signet.bc-2.jp/claim"

VARCHECKS='
        if [ "$varname" = "cmd" ]; then
            bcli=$value;
        elif [ "$varname" = "faucet" ]; then
            faucet=$value;
    '
HELPSTRING="syntax: $0 [--help] [--cmd=<bitcoin-cli path>] [--faucet=<faucet URL>=https://signet.bc-2.jp/claim] [--] [<bitcoin-cli args>]"

source $(dirname $0)/args.sh "$@"

# get address for receiving coins
addr=$($bcli $args getnewaddress) || { echo >&2 "for help, type: $0 --help"; exit 1; }

command -v "curl" > /dev/null \
&& curl -X POST -d "address=$addr" $faucet \
|| wget -qO - --post-data "address=$addr" $faucet

echo
