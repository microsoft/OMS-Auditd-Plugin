/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "Config.h"
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "ConfigTests"
#include <boost/test/unit_test.hpp>

#include "TempFile.h"
#include <stdexcept>

BOOST_AUTO_TEST_CASE( unquoted_value )
{
    TempFile file("/tmp/ConfigTests.", "key = value");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );
    BOOST_CHECK_EQUAL(config.GetString("key"), "value");
}

BOOST_AUTO_TEST_CASE( quoted_value )
{
    TempFile file("/tmp/ConfigTests.", R"(key = "value")");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );
    BOOST_CHECK_EQUAL(config.GetString("key"), "value");
}

BOOST_AUTO_TEST_CASE( quoted_value_with_quotes )
{
    TempFile file("/tmp/ConfigTests.", R"(key = "value\"with\"quotes\"")");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );
    BOOST_CHECK_EQUAL(config.GetString("key"), R"(value"with"quotes")");
}

BOOST_AUTO_TEST_CASE( missing_equal)
{
    TempFile file("/tmp/ConfigTests.", "key value ");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( extra_chars_unquoted )
{
    TempFile file("/tmp/ConfigTests.", "key = value extra");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( extra_chars_quoted )
{
    TempFile file("/tmp/ConfigTests.", R"(key = "value text" extra)");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( missing_end_quote )
{
    TempFile file("/tmp/ConfigTests.", R"(key = "value text)");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( missing_end_quote_with_quotes )
{
    TempFile file("/tmp/ConfigTests.", R"(key = "value\"text\")");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( value_with_comments )
{
    TempFile file("/tmp/ConfigTests.", "# Comment \n key = value # Comment \n #Comment");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );
    BOOST_CHECK_EQUAL(config.GetString("key"), "value");
}

BOOST_AUTO_TEST_CASE( quoted_value_with_comments )
{
    TempFile file("/tmp/ConfigTests.", "# Comment \n key = \"value\" # Comment \n #Comment");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );
    BOOST_CHECK_EQUAL(config.GetString("key"), "value");
}

BOOST_AUTO_TEST_CASE( single_line_json_value )
{
    TempFile file("/tmp/ConfigTests.", "key = { \"key\": \"value\" }");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );

    auto doc = config.GetJSON("key");
    if (doc.HasParseError()) {
        BOOST_FAIL("JSON has parse error");
    }

    BOOST_CHECK_EQUAL(doc.FindMember("key")->value.GetString(), "value");
}

BOOST_AUTO_TEST_CASE( multi_line_json_value )
{
    TempFile file("/tmp/ConfigTests.", "key = {\n \"key\": \"value\" \n }");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );

    auto doc = config.GetJSON("key");
    if (doc.HasParseError()) {
        BOOST_FAIL("JSON has parse error");
    }

    BOOST_CHECK_EQUAL(doc.FindMember("key")->value.GetString(), "value");
}

BOOST_AUTO_TEST_CASE( raw_quoted_value )
{
    TempFile file("/tmp/ConfigTests.", R"(key = R"C(value)C")");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );
    BOOST_CHECK_EQUAL(config.GetString("key"), "value");
}

BOOST_AUTO_TEST_CASE( raw_quoted_value2 )
{
    TempFile file("/tmp/ConfigTests.", R"C(key = R"(value)")C");
    Config config;

    config.Load(file.Path());

    BOOST_CHECK( config.HasKey("key") );
    BOOST_CHECK_EQUAL(config.GetString("key"), "value");
}

BOOST_AUTO_TEST_CASE( raw_quoted_value_bad_end_quote )
{
    TempFile file("/tmp/ConfigTests.", R"C(key = R"(value")C");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( raw_quoted_value_bad_end_quote2 )
{
    TempFile file("/tmp/ConfigTests.", R"C(key = R"(value))C");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( raw_quoted_value_bad_end_quote3 )
{
    TempFile file("/tmp/ConfigTests.", R"C(key = R"(value)X")C");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}

BOOST_AUTO_TEST_CASE( raw_quoted_value_mismatched_delim )
{
    TempFile file("/tmp/ConfigTests.", R"C(key = R"X(value)Y")C");
    Config config;

    BOOST_REQUIRE_THROW(config.Load(file.Path()), std::runtime_error);
}
