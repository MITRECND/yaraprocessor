#!/usr/bin/env python

# Copyright (c) 2013 The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import unittest

from yaraprocessor import Processor


class TestRule(unittest.TestCase):
    def setUp(self):
        self.processor = Processor(['./test.rule'])

    def test_match(self):
        self.processor.data = 'This is a dirty string.'
        results = self.processor.analyze()
        self.assertTrue(results)

    def test_no_match(self):
        self.processor.data = 'This is a clean string.'
        results = self.processor.analyze()
        self.assertFalse(results)


class TestCompiledRule(unittest.TestCase):
    def setUp(self):
        self.processor = Processor(['./test_compiled.rule'],
                                   compiled=True)

    def test_match(self):
        self.processor.data = 'This is a dirty string.'
        results = self.processor.analyze()
        self.assertTrue(results)

    def test_no_match(self):
        self.processor.data = 'This is a clean string.'
        results = self.processor.analyze()
        self.assertFalse(results)


if __name__ == '__main__':
    unittest.main()
