/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include "StringUtils.h"

//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "StringTests"
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE( hex_normal ) {
    std::string hex = "203031";
    std::string out;

    auto ret = decode_hex(out, hex.data(), hex.size());
    BOOST_REQUIRE_EQUAL(ret, 0);
    BOOST_REQUIRE_EQUAL(out, " 01");
}

BOOST_AUTO_TEST_CASE( hex_odd_length ) {
    std::string hex = "20303";
    std::string out;

    auto ret = decode_hex(out, hex.data(), hex.size());
    BOOST_REQUIRE_EQUAL(ret, -1);
    BOOST_REQUIRE_EQUAL(out, "20303");
}

BOOST_AUTO_TEST_CASE( hex_need_escape_low ) {
    std::string hex = "20300A31";
    std::string out;

    auto ret = decode_hex(out, hex.data(), hex.size());
    BOOST_REQUIRE_EQUAL(ret, 1);
    BOOST_REQUIRE_EQUAL(out, " 0\n1");
}

BOOST_AUTO_TEST_CASE( hex_need_escape_high ) {
    std::string hex = "20308031";
    std::string expected;
    std::string out;

    expected = " 0";
    expected.push_back(0x80);
    expected.push_back('1');

    auto ret = decode_hex(out, hex.data(), hex.size());
    BOOST_REQUIRE_EQUAL(ret, 1);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( hex_with_null ) {
    std::string hex = "20300031";
    std::string expected;
    std::string out;

    expected = " 0";
    expected.push_back(0);
    expected.push_back('1');

    auto ret = decode_hex(out, hex.data(), hex.size());
    BOOST_REQUIRE_EQUAL(ret, 1);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( unescape_raw_bad ) {
    std::string in = "";
    std::string expected = "";
    std::string out;

    auto ret = unescape_raw_field(out, nullptr, 0);
    BOOST_REQUIRE_EQUAL(ret, -1);
    BOOST_REQUIRE_EQUAL(out, expected);

    ret = unescape_raw_field(out, in.data(), 0);
    BOOST_REQUIRE_EQUAL(ret, -1);
    BOOST_REQUIRE_EQUAL(out, expected);

    ret = unescape_raw_field(out, in.data(), 10);
    BOOST_REQUIRE_EQUAL(ret, -1);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( unescape_raw_null_str ) {
    std::string in = "(null)";
    std::string expected = "(null)";
    std::string out;

    auto ret = unescape_raw_field(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, 0);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( unescape_raw_none_str ) {
    std::string in = "(none)";
    std::string expected = "(none)";
    std::string out;

    auto ret = unescape_raw_field(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, 0);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( unescape_raw_quoted ) {
    std::string in = "\"value\"";
    std::string expected = "value";
    std::string out;

    auto ret = unescape_raw_field(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, 1);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( unescape_raw_hex ) {
    std::string in = "203031";
    std::string expected = " 01";
    std::string out;

    auto ret = unescape_raw_field(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, 2);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( unescape_raw_hex_with_escape ) {
    std::string in = "20300A31";
    std::string expected = " 0\n1";
    std::string out;

    auto ret = unescape_raw_field(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, 3);
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( tty_escape_test ) {
    std::vector<char> in;
    std::string expected = " ~0\\x00\\x0A\\x01\\x08\\x7F\\x80\\xF7\\xFF";
    std::string out;

    in.push_back(' ');
    in.push_back('~');
    in.push_back('0');
    in.push_back(0);
    in.push_back('\n');
    in.push_back(1);
    in.push_back(0x08);
    in.push_back(0x7F);
    in.push_back(0x80);
    in.push_back(0xF7);
    in.push_back(0xFF);

    tty_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( bash_escape_empty ) {
    std::string in = "";
    std::string expected = "''";
    std::string out;

    auto ret = bash_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( bash_escape_bare ) {
    std::string in = "123";
    std::string expected = "123";
    std::string out;

    auto ret = bash_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( bash_escape_bare_escape ) {
    std::string in = "1\"2'3`$\\";
    std::string expected = "1\\\"2\\'3\\`\\$\\\\";
    std::string out;

    auto ret = bash_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( bash_escape_doublequote ) {
    std::string in = "1\"2' 3`$\\|&;()<>";
    std::string expected = "\"1\\\"2' 3\\`\\$\\\\|&;()<>\"";
    std::string out;

    auto ret = bash_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( bash_escape_singlequote ) {
    std::string in = "1\"2 !3`$\\|&;()<>";
    std::string expected = "'1\"2 !3`$\\|&;()<>'";
    std::string out;

    auto ret = bash_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( bash_escape_bashquote ) {
    std::string in = "1\"2' !3`$\\|&;()<>";
    std::string expected = "$'1\"2\\' !3`$\\|&;()<>";
    std::string out;

    in.push_back(1);
    in.push_back(0x07); // BEL \a
    in.push_back(0x08); // BS \b
    in.push_back(0x09); // TAB \t
    in.push_back(0x0A); // NL \n
    in.push_back(0x0B); // VT \v
    in.push_back(0x0C); // FF \f
    in.push_back(0x0D); // CR \r
    in.push_back(0x1B); // ESC \e
    in.push_back(0x1F);
    in.push_back(0x7F);
    in.push_back(0x80);
    in.push_back(0xF7);
    in.push_back(0xFF);

    expected.append("\\x01");
    expected.append("\\a");
    expected.append("\\b");
    expected.append("\\t");
    expected.append("\\n");
    expected.append("\\v");
    expected.append("\\f");
    expected.append("\\r");
    expected.append("\\e");
    expected.append("\\x1F");
    expected.append("\\x7F");
    expected.append("\\x80");
    expected.append("\\xF7");
    expected.append("\\xFF");
    expected.append("'");

    auto ret = bash_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( bash_escape_bashquote2 ) {
    std::string in;
    std::string expected;
    std::string out;

    in.push_back(0xC9);
    in.push_back(0x28); // (
    in.push_back(0x21); // !

    expected.append("$'");
    expected.append("\\xC9");
    expected.append("(!");
    expected.append("'");

    auto ret = bash_escape_string(out, in.data(), in.size());
    BOOST_REQUIRE_EQUAL(ret, in.size());
    BOOST_REQUIRE_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE( time_whitespace ) {
    BOOST_REQUIRE_EQUAL("test", trim_whitespace(" test "));
    BOOST_REQUIRE_EQUAL("test", trim_whitespace(" test \t\n "));
    BOOST_REQUIRE_EQUAL("test", trim_whitespace("\t\n test \t\n "));
}
