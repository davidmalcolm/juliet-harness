#!/usr/bin/env python

#   Copyright 2021 Red Hat, Inc.
#
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
#   USA

import argparse
from fnmatch import fnmatch
import re
import xml.etree.ElementTree as ET

from firehose.parsers.gcc import parse_file
from firehose.model import Analysis, File, Generator, Metadata, Issue, Location, Message, Point

def parse_make_log(filename):
    """
    Parse FILENAME, returning a firehose.model.Analysis instance.
    """
    with open(filename) as f_in:
        return parse_file(f_in)

def parse_manifest(filename):
    """
    Parse a manifest.xml, returning a firehose.model.Analysis instance
    for the expected results.
    """
    # We expect a "container" element containing multiple "testcase" elements.
    tree = ET.parse(filename)
    root = tree.getroot()
    sut = None
    file_ = File(givenpath=filename, abspath=None)
    stats = None
    generator = Generator(name='sard', version=None)
    metadata = Metadata(generator, sut, file_, stats)
    analysis = Analysis(metadata, [])
    for testcase in root.iter('testcase'):
        for file_ in testcase.iter('file'):
            for flaw in file_.iter('flaw'):
                result = Issue(cwe=None, testid=None,
                               location=Location(file=File(givenpath=file_.get('path'),
                                                           abspath=None),
                                                 function=None,
                                                 point=Point(line=int(flaw.get('line')),
                                                             column=0)),
                               message=Message(text=flaw.get('name')),
                               notes=None,
                               trace=None)
                analysis.results.append(result)
    return analysis

def index_analysis(a):
    """
    Given a firehose.model.Analysis instance generate a dict mapping
    givenpath strings to lists of Issue instances.
    """
    issues_by_givenpath = {}
    for r in a.results:
        if isinstance(r, Issue):
            givenpath = r.location.file.givenpath
            if givenpath in issues_by_givenpath:
                issues_by_givenpath[givenpath].append(r)
            else:
                issues_by_givenpath[givenpath] = [r]
    return issues_by_givenpath

class TextReport:
    def __init__(self):
        self.passes = 0
        self.failures = 0
        self.skipped = 0

    def report_issue(self, result, expectation, issue):
        if result != 'PASS':
            print('%s: %s:%i: %s: %s' % (result,
                                         issue.location.file.givenpath,
                                         issue.location.point.line,
                                         expectation,
                                         issue.message.text))
        if result == 'PASS':
            self.passes += 1
        elif result == 'FAIL':
            self.failures += 1

    def found_issue(self, expected_issue):
        self.report_issue('PASS', 'got expected', expected_issue)

    def missing_issue(self, expected_issue):
        self.report_issue('FAIL', 'missing expected', expected_issue)

    def unexpected_issue(self, actual_issue):
        self.report_issue('FAIL', 'unexpected', actual_issue)

    def skip_path(self, givenpath):
        self.skipped += 1

    def summary(self):
        print('# of passes   %i' % self.passes)
        print('# of failures %i' % self.failures)
        print('# of skipped  %i' % self.skipped)

class Policy:
    def skip_path(self, givenpath):
        raise NotImplementedError

def compare_analyses(expected, actual, report, policy):
    """
    Compare EXPECTED and ACTUAL; call into REPORT
    for issues found in both, or just in one.
    """
    expected_by_givenpath = index_analysis(expected)
    actual_by_givenpath = index_analysis(actual)
    givenpaths = set(expected_by_givenpath.keys()).union(set(actual_by_givenpath.keys()))
    for givenpath in sorted(givenpaths):
        #print(givenpath)
        if givenpath in expected_by_givenpath:
            if policy.skip_path(givenpath):
                report.skip_path(givenpath)
                continue
            if givenpath in actual_by_givenpath:
                # Present in both.  We can't rely on precise line numbers, so for now
                # simply emit that we found the issue.
                for expected_issue in expected_by_givenpath[givenpath]:
                    report.found_issue(expected_issue)
            else:
                # Present in expected; not in actual:
                for expected_issue in expected_by_givenpath[givenpath]:
                    report.missing_issue(expected_issue)
        else:
            # Not in expected; present in actual:
            for actual_issue in actual_by_givenpath[givenpath]:
                report.unexpected_issue(actual_issue)

def is_lto_case(givenpath):
    """
    Juliet's Makefile has letter suffixes for cross-TU testcases e.g.
      CWE415_Double_Free__malloc_free_char_22a.c
      CWE415_Double_Free__malloc_free_char_22b.c
    Identify such testcases.
    """
    return re.match('^.*_[0-9]+[a-z].c$', givenpath)

parser = argparse.ArgumentParser(description='Compare a SARD manifest.xml with a make log')
parser.add_argument('manifest_filename', metavar='MANIFEST.XML', type=str,
                    help='path/filename of manifest.xml')
parser.add_argument('make_log', metavar='MAKE.LOG', type=str,
                    help='path/filename of "make" output')
args = parser.parse_args()

m = parse_manifest(args.manifest_filename)
a = parse_make_log(args.make_log)

class MyPolicy(Policy):
    def skip_path(self, givenpath):
        if not givenpath.startswith('CWE415_Double_Free'):
            return True
        if not givenpath.endswith('.c'):
            return True
        if is_lto_case(givenpath):
            return True

        # Juliet's Makefiles have:
        #   FILTER_OUT=$(wildcard CWE*w32*.c*) $(wildcard CWE*wchar_t*.c*)
        if fnmatch(givenpath, 'CWE*w32*.c*'):
            return True
        if fnmatch(givenpath, 'CWE*wchar_t*.c*'):
            return True

        return False

report = TextReport()
policy = MyPolicy()
compare_analyses(m, a, report, policy)
report.summary()
