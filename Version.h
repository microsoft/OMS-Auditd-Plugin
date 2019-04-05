//
// Created by tad on 3/19/19.
//

#ifndef AUOMS_VERSION_H
#define AUOMS_VERSION_H

#include <string>
#include <array>

class Version {
public:
    explicit Version(const std::string& str): _str(str), _ver() {
        _ver.fill(-1);
        parse();
    }

    inline std::string str() const { return _str; };

    explicit inline operator bool() const noexcept { return _ver[0] > -1; }

    bool operator==(const Version& other) const;
    bool operator<(const Version& other) const;

    inline bool operator!=(const Version& other) const {
        return !(*this == other);
    }

    inline bool operator>(const Version& other) const {
        return other < *this;
    }

    inline bool operator<=(const Version& other) const {
        return !(other < *this);
    }

    inline bool operator>=(const Version& other) const {
        return !(*this < other);
    }

private:
    void parse() noexcept;

    std::string _str;
    std::array<int, 3> _ver;
};


#endif //AUOMS_VERSION_H
