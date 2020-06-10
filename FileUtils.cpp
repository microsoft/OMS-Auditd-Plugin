//
// Created by tad on 3/25/19.
//

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
    std::ofstream out(path, std::ios::binary);
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
