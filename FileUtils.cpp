/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "FileUtils.h"

#include <array>
#include <algorithm>
#include <system_error>
#include <iostream>
#include <fstream>

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>

bool PathExists(const std::string& path) {
    struct stat buf;
    auto ret = stat(path.c_str(), &buf);
    if (ret == 0) {
        return true;
    }
    return false;
}

bool IsDir(const std::string& path) {
    struct stat buf;
    auto ret = stat(path.c_str(), &buf);
    if (ret == 0) {
        return S_ISDIR(buf.st_mode);
    }
    return false;
}

bool IsOnlyRootWritable(const std::string& path) {
    struct stat st;
    auto ret = stat(path.c_str(), &st);
    if (ret != 0 || st.st_uid != 0) {
        return false;
    }
    if (st.st_gid != 0) {
        // If gid is not root, then both group and other write bit must be cleared
        return (st.st_mode & (S_IWGRP|S_IWOTH)) == 0;
    } else {
        // If gid is root, then only other write bit must be cleared
        return (st.st_mode & S_IWOTH) == 0;
    }
}
std::string Dirname(const std::string& path) {
    std::string dir = path;
    while(dir.back() == '/') {
        dir.resize(dir.size()-1);
    }

    auto idx = dir.rfind('/');
    if (idx != std::string::npos && idx != 0) {
        return dir.substr(0, idx);
    }

    return dir;
}

std::string Basename(const std::string& path, const std::string& suffix) {
    std::string name = path;
    while(name.back() == '/') {
        name.resize(name.size()-1);
    }

    auto idx = name.rfind('/');
    if (idx != std::string::npos && idx != 0) {
        name = name.substr(idx+1);
    }

    if (name.size() >= suffix.size() && name.compare(name.size()-suffix.size(), suffix.size(), suffix) == 0) {
        name.resize(name.size()-suffix.size());
    }
    return name;
}

std::vector<std::string> GetDirList(const std::string& dir) {
    std::vector<std::string> files;
    std::array<char, 4096> buffer;

    auto dirp = opendir(dir.c_str());
    if (dirp == nullptr) {
        throw std::system_error(errno, std::system_category(), "opendir("+dir+")");
    }

    struct dirent* dent;
    while((dent = readdir(dirp)) != nullptr) {
        std::string name(&dent->d_name[0]);
        if (name != "." && name != "..") {
            files.emplace_back(name);
        }
    }
    closedir(dirp);

    std::sort(files.begin(), files.end());
    return files;
}

std::vector<std::string> ReadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        throw std::runtime_error("Failed to open '" + path + "'");
    }
    std::vector<std::string> lines;
    for (std::string line; std::getline(in, line); ) {
        lines.emplace_back(line);
    }
    return lines;
}

void WriteFile(const std::string& path, const std::vector<std::string>& lines) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        throw std::runtime_error("Failed to open '" + path + "'");
    }
    for (auto& line: lines) {
        out << line << std::endl;
    }
    out.close();
}

void AppendFile(const std::string& path, const std::vector<std::string>& lines) {
    std::ofstream out(path, std::ios::binary | std::ios::ate);
    if (!out.is_open()) {
        throw std::runtime_error("Failed to open '" + path + "'");
    }
    for (auto& line: lines) {
        out << line << std::endl;
    }
    out.close();
}

bool RemoveFile(const std::string& path, bool throw_on_error) {
    auto ret = unlink(path.c_str());
    if (ret != 0) {
        if (errno == ENOENT) {
            return false;
        }
        if (throw_on_error) {
            throw std::system_error(errno, std::system_category(), "unlink("+path+")");
        }
        return false;
    }
    return true;
}
