//
// Created by tad on 3/19/19.
//

#include "Version.h"

#include "StringUtils.h"

bool Version::operator==(const Version& other) const {
    for (int i = 0; i < _ver.size(); ++i) {
        if (_ver[i] != other._ver[i]) {
            return false;
        }
    }
    return true;
}

bool Version::operator<(const Version& other) const {
    for (int i = 0; i < _ver.size(); ++i) {
        if (_ver[i] != other._ver[i]) {
            return _ver[i] < other._ver[i];
        }
    }
    return false;
}

void Version::parse() noexcept {
    auto parts = split(_str, ".-_");
    if (parts.empty()) {
        return;
    }

    for (int i = 0; i < parts.size(); ++i) {
        try {
            _ver[i] = stoi(parts[0]);
        } catch (std::exception&) {
            _ver[i] = -1;
        }
    }

    if (_ver[0] != -1) {
        for (int i = 1; i < _ver.size(); ++i) {
            if (_ver[i] == -1) {
                _ver[i] = 0;
            }
        }
    }
}
