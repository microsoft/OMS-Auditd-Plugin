/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved. 

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "UserDB.h"
//#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "UserDBTests"
#include <boost/test/unit_test.hpp>

#include "Logger.h"
#include "TempDir.h"
#include <fstream>
#include <stdexcept>

extern "C" {
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
};

const std::string passwd =
        "root:x:0:0:root:/root:/bin/bash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "user:x:1000:1000:User,,,:/home/user:/bin/bash\n";

const std::string passwd2 =
        "root:x:0:0:root:/root:/bin/bash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "user:x:1000:1000:User,,,:/home/user:/bin/bash\n"
        "test:x:1001:1001:Test,,,:/home/test:/bin/bash\n";

const std::string group =
        "root:x:0:\n"
        "adm:x:4:user\n"
        "nogroup:x:65534:\n"
        "user:x:1000:\n";

const std::string group2 =
        "root:x:0:\n"
        "adm:x:4:user\n"
        "nogroup:x:65534:\n"
        "user:x:1000:\n"
        "test:x:1001:\n";

void write_file(const std::string& path, const std::string& text) {
    std::ofstream out;
    out.exceptions(std::ofstream::failbit|std::ofstream::badbit|std::ofstream::eofbit);
    out.open(path);
    out << text;
    out.close();
}

void replace_file(const std::string& path, const std::string& text)
{
    std::string tmp_path = path + ".tmp";
    write_file (tmp_path, text);

    if (unlink(path.c_str()) != 0) {
        throw std::system_error(errno, std::system_category());
    }

    if (rename(tmp_path.c_str(), path.c_str()) != 0) {
        throw std::system_error(errno, std::system_category());
    }
}

BOOST_AUTO_TEST_CASE( basic_test ) {
    TempDir dir("/tmp/UserDBTests");

    write_file(dir.Path()+"/passwd", passwd);
    write_file(dir.Path()+"/group", group);

    UserDB user_db(dir.Path());

    user_db.Start();

    // Wait for threads to finish starting
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    BOOST_CHECK_EQUAL(user_db.GetUserName(0), "root");
    BOOST_CHECK_EQUAL(user_db.GetUserName(65534), "nobody");
    BOOST_CHECK_EQUAL(user_db.GetUserName(1000), "user");
    BOOST_CHECK_EQUAL(user_db.GetUserName(1001), "");

    BOOST_CHECK_EQUAL(user_db.GetGroupName(0), "root");
    BOOST_CHECK_EQUAL(user_db.GetGroupName(65534), "nogroup");
    BOOST_CHECK_EQUAL(user_db.GetGroupName(4), "adm");
    BOOST_CHECK_EQUAL(user_db.GetGroupName(1000), "user");
    BOOST_CHECK_EQUAL(user_db.GetGroupName(1001), "");

    replace_file(dir.Path()+"/passwd", passwd2);
    replace_file(dir.Path()+"/group", group2);

    BOOST_CHECK_EQUAL(user_db.GetUserName(1001), "");
    BOOST_CHECK_EQUAL(user_db.GetGroupName(1001), "");

    // Wait for db to update after file changes
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    BOOST_CHECK_EQUAL(user_db.GetUserName(1001), "test");
    BOOST_CHECK_EQUAL(user_db.GetGroupName(1001), "test");

    user_db.Stop();
}
