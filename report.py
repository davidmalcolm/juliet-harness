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

# Tests to skip since -fanalyzer doesn't implement them
# (or doesn't implement them yet)
UNIMPLEMENTED_TESTS = ['Addition_of_Data_Structure_Sentinel',
                       'Assigning_Instead_of_Comparing', # TODO: use -Wall ?
                       'Assignment_of_Fixed_Address_to_Pointer',
                       'Attempt_to_Access_Child_of_Non_Structure_Pointer',
                       'Buffer_Overflow',
                       'Buffer_Underwrite',
                       'Buffer_Overread',
                       'Buffer_Underread',
                       'Comparing_Instead_of_Assigning', # TODO: use -Wall ?
                       'Dead_Code',
                       'Divide_by_Zero',
                       'Duplicate_Operations_on_Resource',
                       'Embedded_Malicious_Code',
                       'Error_Without_Action',
                       'Expression_Always_False', # TODO: use -Wall ?
                       'Expression_Always_True', # TODO: use -Wall ?
                       'Function_Call_With_Incorrect_Number_of_Arguments', # TODO: use -Wall ?
                       'Function_Call_With_Incorrect_Variable_or_Reference_as_Argument', # TODO: use -Wall ?
                       'Improper_Initialization',
                       'Improper_Locking',
                       'Incorrect_Block_Delimitation', # TODO: use -Wall ?
                       'Incorrect_Check_of_Function_Return_Value',
                       'Incorrect_Conversion_Between_Numeric_Types',
                       'Incorrect_Pointer_Scaling',
                       'Infinite_Loop',
                       'Info_Exposure_Environment_Variables',
                       'Insecure_Temporary_File',
                       'Integer_Overflow',
                       'Integer_Underflow',
                       'Logic_Time_Bomb',
                       'Missing_Default_Case_in_Switch', # TODO: use -Wall ?
                       'Missing_Reference_to_Active_File_Descriptor_or_Handle',
                       'Missing_Release_of_File_Descriptor_or_Handle',
                       'Multiple_Binds_Same_Port',
                       'Numeric_Truncation_Error',
                       'Omitted_Break_Statement_in_Switch', # TODO: use -Wall ?
                       'Operation_on_Resource_in_Wrong_Phase_of_Lifetime',
                       'OS_Command_Injection',
                       'Poor_Code_Quality',
                       'Race_Condition_Within_Thread',
                       'Reachable_Assertion',
                       'Reliance_on_Data_Memory_Layout',
                       'Resource_Exhaustion',
                       'Signal_Handler_Race_Condition',
                       'Signed_to_Unsigned_Conversion_Error',
                       'Suspicious_Comment',
                       'TOC_TOU',
                       'Trapdoor',
                       'Type_Confusion',
                       'Unchecked_Error_Condition',
                       'Unchecked_Return_Value',
                       'Untrusted_Search_Path',
                       'Unchecked_Loop_Condition',
                       'Uncontrolled_Format_String',
                       'Uncontrolled_Mem_Alloc',
                       'Uncontrolled_Search_Path_Element',
                       'Undefined_Behavior_for_Input_to_API',
                       'Unexpected_Sign_Extension',
                       'Unlock_of_Resource_That_is_Not_Locked',
                       'Unsigned_to_Signed_Conversion_Error',
                       'Unused_Variable', # TODO: use -Wall ?
                       'Use_of_Incorrect_Operator',
                       'Use_of_Pointer_Subtraction_to_Determine_Size',
                       'Use_of_sizeof_on_Pointer_Type', # TODO: use -Wall ?
                       'Write_What_Where_Condition']

# Tests that ought to work, but aren't for some reason
# (and need investigating)
TESTS_TO_INVESTIGATE = ['Free_Memory_Not_on_Heap',
                        'Free_Pointer_Not_at_Start_of_Buffer',
                        'Improper_Resource_Shutdown',
                        'Incomplete_Cleanup',
                        'Memory_Leak',
                        'NULL_Deref_From_Return',
                        'Uncontrolled_Recursion',
                        'Use_of_Uninitialized_Variable']

class MyPolicy(Policy):
    def skip_path(self, givenpath):
        for test_name in UNIMPLEMENTED_TESTS:
            if test_name in givenpath:
                return True
        for test_name in TESTS_TO_INVESTIGATE:
            if test_name in givenpath:
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
