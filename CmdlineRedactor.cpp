/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "CmdlineRedactor.h"

#include "Config.h"
#include "FileUtils.h"
#include "Logger.h"
#include "StringUtils.h"

std::shared_ptr<CmdlineRedactionRule> CmdlineRedactionRule::LoadFromFile(const std::string& path) {
    Config config;
    try {
        config.Load(path);

        std::string replacement_char = "*";
        if (config.HasKey("replacement_char")) {
            replacement_char = config.GetString("replacement_char");
            if (replacement_char.length() > 1) {
                replacement_char.resize(1);
                Logger::Warn("Configured replacement_char (%s) is too long, truncating to 1 char", replacement_char.c_str());
            }
        }

        if (!config.HasKey("regex")) {
            Logger::Error("CmdlineRedactionRule::LoadFromFile(): Config (%s) is missing the 'regex' value", path.c_str());
            return nullptr;
        }
        std::string regex = config.GetString("regex");

        auto ret = std::make_shared<CmdlineRedactionRule>(regex, replacement_char[0]);
        if (!ret->Compile()) {
            Logger::Error("CmdlineRedactionRule::LoadFromFile(): Failed to load from (%s): Invalid regex: %s", path.c_str(), ret->CompileError().c_str());
            return nullptr;
        }
        return ret;
    } catch (std::exception& ex) {
        Logger::Error("CmdlineRedactionRule::LoadFromFile(): Failed to load from (%s): %s", path.c_str(), ex.what());
    }

    return nullptr;
}

bool CmdlineRedactionRule::Apply(std::string& cmdline) const {
    if (cmdline.empty()) {
        return false;
    }
    auto res = false;
    size_t num_groups = _regex.NumberOfCapturingGroups() + 1;
    re2::StringPiece groups[num_groups];
    re2::StringPiece text(cmdline);
    size_t idx = 0;
    size_t end = text.size();
    while (idx < end) {
        if (!_regex.Match(text, idx, end, re2::RE2::UNANCHORED, &groups[0], num_groups)) {
            break;
        }
        for (int i = 1; i < num_groups; ++i) {
            if (groups[i].data() != nullptr) {
                char * start = cmdline.data() + (groups[i].data() - text.data());
                std::fill(start, start + groups[i].size(), _replacement_char);
            }
        }
        res = true;
        idx += groups[0].size();
    }
    return res;
}

void CmdlineRedactor::AddRule(const std::shared_ptr<CmdlineRedactionRule>& rule) {
    _rules.emplace_back(rule);
}

void CmdlineRedactor::LoadFromDir(const std::string& dir) {
    if (!PathExists(dir)) {
        return;
    }
    std::vector<std::string> files;
    try {
        files = GetDirList(dir);
    } catch (std::exception& ex) {
        Logger::Error("CmdlineRedactor::LoadFromDir(): Failed to read dir (%s): %s", dir.c_str(), ex.what());
        return;
    }
    std::sort(files.begin(), files.end());
    for (auto& name: files) {
        if (ends_with(name, ".conf")) {
            auto rule = CmdlineRedactionRule::LoadFromFile(dir + "/" + name);
            if (rule) {
                _rules.emplace_back(rule);
            }
        }
    }
}

bool CmdlineRedactor::ApplyRules(std::string& cmdline) const {
    auto res = false;
    for (auto& rule: _rules) {
        if (rule->Apply(cmdline)) {
            res = true;
        }
    }
    return res;
}
