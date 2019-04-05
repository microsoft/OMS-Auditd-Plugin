//
// Created by tad on 3/25/19.
//

#ifndef AUOMS_FILEUTILS_H
#define AUOMS_FILEUTILS_H

#include <string>
#include <vector>

bool PathExists(const std::string& path);

bool IsDir(const std::string& path);

std::vector<std::string> GetDirList(const std::string& dir);

std::vector<std::string> ReadFile(const std::string& path);

void WriteFile(const std::string& path, const std::vector<std::string>& lines);

#endif //AUOMS_FILEUTILS_H
