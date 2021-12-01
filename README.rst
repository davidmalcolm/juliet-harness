Harness for testing GCC static analyzer with Juliet test suite
==============================================================

GCC 10 onwards implements a static analysis pass for C code::

  https://gcc.gnu.org/wiki/DavidMalcolm/StaticAnalyzer

The Juliet Test Suite is a collection of test cases for use in testing
static analysis tools, created by the NSA’s Center for Assured Software
(CAS)::

  https://samate.nist.gov/SARD/around.php#juliet_documents

This repository contains scripts for testing GCC's -fanalyzer with Juliet.

Tested with Juliet 1.3::

  $ sha256sum Juliet_Test_Suite_v1.3_for_C_Cpp.zip
  ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb  Juliet_Test_Suite_v1.3_for_C_Cpp.zip

My current method:

- Download Juliet test suite for C/C++ from
  https://samate.nist.gov/SARD/testsuites/juliet/Juliet_Test_Suite_v1.3_for_C_Cpp.zip

- Unpack somewhere

- Build it against a test version of GCC, e.g. via:
    (make -k LANG=C CFLAGS="-fanalyzer -c -B PATH_TO_GCC_UNDER_TEST" CC="PATH_TO_XGCC_UNDER_TEST" 2>&1) | tee make.log

    .. note::  the GCC result parser used by `report.py` doesn't currently do a
       good job of handling parallel builds, and requires `LANG=C`.

- Compare the expected results against the actual results via::

     ./report.py path/to/manifest.xml path/to/make.log

  where the `manifest.xml` is within the top-level `C` directory of the unpacked
  `Juliet_Test_Suite_v1.3_for_C_Cpp.zip` archive.
