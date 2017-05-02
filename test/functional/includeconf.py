#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -includeconf directive."""

import os
from test_framework.test_framework import BitcoinTestFramework
# from test_framework.util import assert_equal

class IncludeConfTest(BitcoinTestFramework):

    def setup_chain(self):
        super().setup_chain()
        # Create additional config files
        # - tmpdir/node0/relative.conf
        with open(os.path.join(self.options.tmpdir+"/node0", "relative.conf"), "w", encoding="utf8") as f:
            f.write("uacomment=relative\nincludeconf=../global.conf\n")
        # - tmpdir/global.conf
        with open(os.path.join(self.options.tmpdir, "global.conf"), "w", encoding="utf8") as f:
            f.write("uacomment=global\nincludeconf=globrel.conf\n")
        # - tmpdir/globrel.conf (also has circular include into global.conf)
        with open(os.path.join(self.options.tmpdir, "globrel.conf"), "w", encoding="utf8") as f:
            f.write("uacomment=globrel\nincludeconf=global.conf")
        # Append includeconf to bitcoin.conf before initialization
        with open(os.path.join(self.options.tmpdir+"/node0", "bitcoin.conf"), 'a', encoding='utf8') as f:
            f.write("uacomment=main\nincludeconf=relative.conf\n")
        # subversion should end with "(main; relative; global; globrel)/"

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = self.setup_nodes()

    def run_test (self):
        '''
        Create a series of configuration files that load each other using
        includeconf (done in setup_chain). We check that:
        1. The files are indeed loaded.
        2. The load ordering is correct.
        3. Circular includes are guarded against.
        '''

        nwinfo = self.nodes[0].getnetworkinfo()
        subversion = nwinfo["subversion"]
        assert subversion.endswith("(main; relative; global; globrel)/")

if __name__ == '__main__':
    IncludeConfTest().main()
