#pragma once
#include <vector>
#include <map>
#include "TargetExecutive.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  class TargetContainer {
    TargetProgram *program;
    OracleFactory *oracleFactory;
    u160 baseAddress;
    public:
      TargetContainer();
      ~TargetContainer();
      vector<bool> analyze() { return oracleFactory->analyze(); }
      map<string,vector<bool>> getFunVul() { return oracleFactory->getFun();}
      TargetExecutive loadContract(bytes code, ContractABI ca);
      TargetExecutive loadMainContract(bytes code, ContractABI ca);
      void resetVulnerability() {  oracleFactory->resetVulnerability();}
  };
}
