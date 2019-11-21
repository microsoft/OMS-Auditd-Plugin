//
// Created by tad on 4/15/19.
//

#ifndef AUOMS_EXECVECONVERTER_H
#define AUOMS_EXECVECONVERTER_H

#include "Event.h"

#include <vector>

class ExecveConverter {
public:
    void Convert(std::vector<EventRecord> execve_recs, std::string& cmdline);

    // Assumes that raw_cmdline contains NUL delimited args
    static void ConvertRawCmdline(const std::string_view& raw_cmdline, std::string& cmdline);

private:
    std::string _tmp_val;
    std::string _unescaped_val;
};


#endif //AUOMS_EXECVECONVERTER_H
