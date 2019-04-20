//
// Created by tad on 4/15/19.
//

#ifndef AUOMS_EXECVECONVERTER_H
#define AUOMS_EXECVECONVERTER_H

#include "Event.h"

#include <vector>

class ExecveConverter {
public:
    void Convert(std::vector<EventRecord> execve_recs);
    std::string& Cmdline() { return _cmdline; }
private:
    std::string _tmp_val;
    std::string _unescaped_val;
    std::string _cmdline;
};


#endif //AUOMS_EXECVECONVERTER_H
