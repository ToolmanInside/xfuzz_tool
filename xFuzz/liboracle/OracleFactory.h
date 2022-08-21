#pragma once
#include <iostream>
#include<map>

#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

class OracleFactory {
    MultipleFunction functions;
    SingleFunction function;
    vector<bool> vulnerabilities;
    map<string,vector<bool>> funVulnerabilities ;
  public:
    void initialize();
    void finalize();
    void save(OpcodeContext ctx);

    vector<bool> analyze();
    map<string,vector<bool>> getFun()
    {
      return funVulnerabilities;
    };

    void resetVulnerability()
    {
      vulnerabilities.clear();
      funVulnerabilities.clear();
    }
};
