/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "CmdlineRedactorTests"
#include <boost/test/unit_test.hpp>
#include "CmdlineRedactor.h"

#include "TempDir.h"
#include "FileUtils.h"

#include <vector>

BOOST_AUTO_TEST_CASE( basic_redact_rule_test ) {

    CmdlineRedactionRule rule("test.conf", "test", R"regex(-arg (\S+))regex", '*');

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
    CmdlineRedactionRule rule("test.conf", "test", R"regex(-arg (\S+))regex", '*');

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

BOOST_AUTO_TEST_CASE( required_redact ) {
    TempDir dir("/tmp/CmdlineRedactionTest.");

    WriteFile(dir.Path() +"/" + "test1.conf", {
        R"LINE(regex=R"regex(-arg (\S+))regex")LINE",
    });

    WriteFile(dir.Path() +"/" + "test.requires", {
        "test1.conf",
        "test2.conf",
    });

    CmdlineRedactor r;
    if (r.LoadFromDir(dir.Path(), false)) {
        BOOST_FAIL("CmdlineRedactor.LoadFromDir should have returned false");
    }

    auto missing = r.GetMissingRules();
    BOOST_REQUIRE_EQUAL(missing.size(), 1);
    BOOST_REQUIRE_EQUAL(missing[0], "test2.conf");

    std::string cmdline = "test -arg stuff";
    std::string names;
    if (!r.ApplyRules(cmdline, names)) {
        BOOST_FAIL("CmdlineRedactor.ApplyRules did not redact");
    }

    BOOST_REQUIRE_EQUAL(names, CmdlineRedactor::REDACT_RULE_MISSING_NAME);
    BOOST_REQUIRE_EQUAL(cmdline, CmdlineRedactor::REDACT_RULE_MISSING_TEXT);

    WriteFile(dir.Path() +"/" + "test2.conf", {
            R"LINE(regex=R"regex(-pass (\S+))regex")LINE",
    });

    if (!r.LoadFromDir(dir.Path(), false)) {
        BOOST_FAIL("CmdlineRedactor.LoadFromDir should have returned true");
    }

    cmdline = "test -arg stuff";
    if (!r.ApplyRules(cmdline, names)) {
        BOOST_FAIL("CmdlineRedactor.ApplyRules did not redact");
    }

    BOOST_REQUIRE_EQUAL(names, "test1");
    BOOST_REQUIRE_EQUAL(cmdline, "test -arg *****");

}
