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

"""
Scan data streams with Yara using various algorithms.
"""

# Standard Imports
import os
import sys
import errno
import logging
import argparse
import binascii

# Libary Imports
import yara


class ProcessorException(Exception):
    pass


class Processor(object):
    """
    A wrapper to Yara.
    """

    def __init__(self, rule_files, processing_mode='raw',
                 compiled=False, **kwargs):
        """
        Default initializer.

        Keyword arguments:
        rule_files -- (List) Filepaths to yara rule files.
                      (Ex. ['/path/to/file1', '/path/to/file2'])

        processing_mode -- (String) Mode used in processing data. Allowed
                           options include; fixed_buffer, sliding_window,
                           and raw. Default is raw mode.

        compiled -- (Boolean) If True, treat the provided rule file as compiled.

        Optional arguments:
        "fixed_buffer" processing mode:
        Data will be processed by yara in fixed sized buffers.

            buffer_size -- (Integer) Amount of data to buffer
                           before processing in bytes. Default is
                           1024 bytes.

        "sliding_window" processing mode:
        Data will be processed by yara in fixed sized buffers, but it
        is possible for buffers to "overlap" by controlling the buffer
        increment.

            buffer_size -- (Integer) Amount of data to process in bytes.
                           Default is 1024 bytes.

            window_step -- (Integer) Amount to increment window per chunk.
                           Default is 1 byte.

        """
        # Get handle to logger
        self.logger = logging.getLogger('yaraprocessor')

        # Validate all file names to ensure they exist and can be read
        for f in rule_files:
            if os.path.isfile(f):
                try:
                    with open(f):
                        pass

                except IOError:
                    raise IOError((errno.EACCES, 'Cannot open/read file.', f))

            else:
                raise IOError((errno.ENOENT, 'Cannot find file.', f))

        if not compiled:
            self._rule_files = self._prepare_rules(rule_files)

            # Try to load the rules into yara
            try:
                self._rules = yara.compile(filepaths=self._rule_files)
            except yara.SyntaxError as e:
                err = ('Rule syntax error. If using compiled rules, you must '
                       'pass the "compiled" argument. Original error: %s' % e)
                raise ProcessorException(err)
            except yara.Error:
                raise

        else:  # rules are compiled
            try:
                # yara.load only accepts a single file
                assert(len(rule_files) == 1)
            except AssertionError:
                err = ('Compiled rules must be compiled to one file. Loading '
                       'from compiled rules does not support multiple rule files.')
                raise ProcessorException(err)

            self._rule_files = rule_files[0]

            try:
                self._rules = yara.load(self._rule_files)
            except yara.Error as e:
                err = ('Generic error loading compiled rules. '
                       'Original error: %s' % e)
                raise ProcessorException(err)

        # Validate that the processing mode is supported
        self._allowed_modes = ['raw', 'fixed_buffer', 'sliding_window']
        if not processing_mode.lower() in self._allowed_modes:
            raise ProcessorException("%s is not a supported processing mode." \
                                     % processing_mode)

        self._processing_mode = processing_mode

        # Optional arguments with defaults
        self._buffer_size = kwargs.get('buffer_size', 1024)
        self._window_step = kwargs.get('window_step', 1)

        # Set window_step to buffer size when processing in fixed buffer mode
        # This makes the analysis code simpler
        if self._processing_mode == 'fixed_buffer':
            self._window_step = self._buffer_size

        # Attribute used to hold data and results to be processed
        self._raw_results = []
        self._formatted_results = []
        self.data = ''

        # Private variables for buffering and window processing
        self._current = ''
        self._next = None
        self._window_index = 0
        self._offset = 0

    def __str__(self):
        """
        Pretty way to print a processor.
        """
        s = 'Processor ' + __name__
        if self._rule_files:
            s += ' running with rules ' + ' '.join(self._rule_files.values())

        return s

    def _prepare_rules(self, rules):
        """
        Convert a list of rule files to a dict of rule files.

        Keyword arguments:
        rules -- list of rule files as fully qualified paths

        Yara expects a dictionary of {Namespaces:filepaths}. Returns a
        dictionary of rule files.

        """
        results = {}
        for i, fn in enumerate(rules):
            results['RuleFile%s' % i] = fn

        return results

    def _window(self, sequence, size=2, step=1):
        """
        Returns a sliding window (of width n) over data from the iterable.

        The window increments by 'step'.
        s -> (s0,s1,...s[n-1]), (s0+step,s1+step,...,sn), ...

        """
        i = 0
        while True:
            result = sequence[i: i + size]
            if not result:
                break

            else:
                i = i + step
                yield result

    def analyze(self, data=None):
        """
        Analyze data with yara.

        Calls yara's "match" function on self.data and
        returns the results returned by match.

        """
        if not data:
            data = self.data

        for r in self._rules.match(data=data):
            result = {'result': r.rule,
                      'strings': [],
                      'subtype': 'scan_result'}

            for s in r.strings:
                result['strings'].append({'offset': self._offset + s[0],
                                          'rule_id': s[1],
                                          'string': binascii.hexlify(s[2])})

            self._raw_results.append(r)
            self._formatted_results.append(result)

        if self._processing_mode == 'raw':
            self._offset += len(data)

        return self.results

    @property
    def results(self):
        """
        Get the analysis results.
        """
        return self._formatted_results

    def clear_results(self):
        """
        Clear the current set of results.
        """
        self._raw_results = []
        self._formatted_results = []

    @property
    def data(self):
        """
        Get the data to be analyzed by yara.
        """
        return self._current

    @data.setter
    def data(self, value):
        """
        Set the data to be analyzed by yara.

        This behaves differently based on the processing mode
        being used.

        If set to "raw", data is a simple buffer.

        If set to "fixed_buffer", data will be buffered until that size
        is reached. When reached, the data will automatically be analyzed,
        and the buffer will be cleared. If data is larger than the fixed_buffer
        any extra will be buffered into the next chunk.

        If set to "sliding_window", data will be buffered similar to
        "fixed_buffer" mode. However, the analysis window will increment
        based on the buffer size. For example, with a buffer size set to 5,
        a data stream of '123456789' would be analyzed in the following chunks:

        12345
        23456
        34567
        45678
        56789

        The option "window_step" controls the increment between windows. For
        example, a window step of 2 changes the above example to:

        12345
        34567
        56789

        """
        self._current = value

        if self._processing_mode != 'raw':
            if self._current and \
               len(self._current[self._window_index:]) >= self._buffer_size:
                for chunk in self._window(self._current[self._window_index:],
                                          size=self._buffer_size,
                                          step=self._window_step):
                    # Analyze each chunk and concatenate the results
                    self.analyze(''.join(chunk))

                    if self._processing_mode == 'fixed_buffer':
                        self._offset += len(chunk)
                    elif self._processing_mode == 'sliding_window':
                        self._offset += self._window_step

                # Update the index
                self._window_index = len(self._current)

if __name__ == '__main__':
    """
    Helper code used to test yaraprocessor.
    """
    # Setup logging
    logger = logging.getLogger('yaraprocessor')
    logger.setLevel(logging.DEBUG)
    consoleHandler = logging.StreamHandler(stream=sys.stdout)
    consoleHandler.setFormatter(logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s%(message)s'))
    logger.addHandler(consoleHandler)

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Analyze data with Yara")

    parser.add_argument(
        '--mode',
        choices=['raw', 'fixed_buffer', 'sliding_window'],
        default='raw',
        help='Set the operating mode for yara. Default is "raw".')

    parser.add_argument(
        '--input',
        nargs='?',
        type=argparse.FileType('r'),
        required=True,
        help='File to read data from for analysis.')

    parser.add_argument(
        '--rules',
        nargs='*',
        required=True,
        help='Rule files for use in Yara.')

    parser.add_argument(
        '--compiled',
        action='store_true',
        help='Treat provided rule file as compiled. Note, all rules must \
              be compiled to a single file.'
    )

    parser.add_argument(
        '--size',
        type=int,
        default=5,
        help='If using fixed_buffer or sliding_window mode, \
              set the size of the buffer/window. Default is 5.')

    parser.add_argument(
        '--step',
        type=int,
        default=1,
        help='Window step. Default is 1.')

    args = parser.parse_args()
    data = args.input.read()

    logger.debug('Building Processor with rules:')
    for i, each in enumerate(args.rules):
        logger.debug('    %i) %s' % (i, each))

    if args.compiled:
        logger.debug('Treating rule file as compiled.')

    logger.debug('Operating in %s mode.' % args.mode)
    if args.mode != 'raw':
        logger.debug('Buffer/Window size is %s' % args.size)
        logger.debug('Window step is %s' % args.step)

        p = Processor(args.rules, processing_mode=args.mode,
                      compiled=args.compiled, buffer_size=args.size,
                      window_step=args.step)
        p.data += data

    else:
        p = Processor(args.rules, compiled=args.compiled)
        p.data += data
        results = p.analyze()

    if p.results:
        for match in p.results:
            logger.debug('Match found; %s', match)
