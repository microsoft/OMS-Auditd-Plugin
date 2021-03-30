/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "CmdlineRedactorTests"
#include <boost/test/unit_test.hpp>
#include "CmdlineRedactor.h"

#include <vector>

BOOST_AUTO_TEST_CASE( basic_redact_rule_test ) {

    CmdlineRedactionRule rule("test", R"regex(-arg (\S+))regex", '*');

    if (!rule.CompiledOK()) {
        BOOST_FAIL(std::string("rule.Compile() failed: ") + rule.CompileError());
    }

    std::vector<std::tuple<std::string,std::string, bool>> tests(
    {
              {"test", "test", false},
              {"test -arg badstuff", "test -arg ********", true},
              {"test -arg badstuff -arg2 not-bad-stuff", "test -arg ******** -arg2 not-bad-stuff", true},
              {"test -arg badstuff -arg2 not-bad-stuff -arg badstuff", "test -arg ******** -arg2 not-bad-stuff -arg ********", true},
    });

    for (auto& test : tests) {
        std::string str = std::get<0>(test);
        auto r = rule.Apply(str);
        if (r != std::get<2>(test)) {
            BOOST_FAIL("CmdlineRedactionRule::Check() returned invalid result");
        }
        if (str != std::get<1>(test)) {
            BOOST_FAIL("CmdlineRedactionRule::Check() redaction is wrong: Expected '" + std::get<1>(test) + "', got '" + str + '"');
        }
    }
}

BOOST_AUTO_TEST_CASE( basic_redact_test ) {
    CmdlineRedactionRule rule("test", R"regex(-arg (\S+))regex", '*');

    if (!rule.CompiledOK()) {
        BOOST_FAIL(std::string("rule.Compile() failed: ") + rule.CompileError());
    }

    std::vector<std::tuple<std::string,std::string, bool>> tests(
            {
                    {"test", "test", false},
                    {"test -arg badstuff", "test -arg ********", true},
                    {"test -arg badstuff -arg2 not-bad-stuff", "test -arg ******** -arg2 not-bad-stuff", true},
                    {"test -arg badstuff -arg2 not-bad-stuff -arg badstuff", "test -arg ******** -arg2 not-bad-stuff -arg ********", true},
            });

    for (auto& test : tests) {
        std::string str = std::get<0>(test);
        auto r = rule.Apply(str);
        if (r != std::get<2>(test)) {
            BOOST_FAIL("CmdlineRedactionRule::Check() returned invalid result");
        }
        if (str != std::get<1>(test)) {
            BOOST_FAIL("CmdlineRedactionRule::Check() redaction is wrong: Expected '" + std::get<1>(test) + "', got '" + str + '"');
        }
    }
}