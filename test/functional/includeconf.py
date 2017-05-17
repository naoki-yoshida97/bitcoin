#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -includeconf directive."""

import os
from test_framework.test_framework import BitcoinTestFramework

class IncludeConfTest(BitcoinTestFramework):

    def setup_chain(self):
        super().setup_chain()
        # Create additional config file
        # - tmpdir/node0/relative.conf
        with open(os.path.join(self.options.tmpdir+"/node0", "relative.conf"), "w", encoding="utf8") as f:
            f.write("uacomment=relative\n")
        with open(os.path.join(self.options.tmpdir+"/node0", "bitcoin.conf"), 'a', encoding='utf8') as f:
            f.write("uacomment=main\nincludeconf=relative.conf\n")
        # subversion should end with "(main; relative)/"

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()

    def run_test (self):
        '''
        Create an additional configuration file that is loaded from the main
        bitcoin.conf via includeconf (done in setup_chain). We check that:
        1. The files are indeed loaded.
        2. The load ordering is correct.
        '''

        nwinfo = self.nodes[0].getnetworkinfo()
        subversion = nwinfo["subversion"]
        assert subversion.endswith("main; relative)/")

if __name__ == '__main__':
    IncludeConfTest().main()
