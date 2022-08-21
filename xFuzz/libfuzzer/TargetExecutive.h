#pragma once
#include <vector>
#include <map>
#include <liboracle/OracleFactory.h>
#include "Common.h"
#include "TargetProgram.h"
#include "ContractABI.h"
#include "TargetContainerResult.h"
#include "Util.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct RecordParam {
    u64 lastpc = 0;
    bool isDeployment = false;
  };
  class TargetExecutive {
      TargetProgram *program;
      OracleFactory *oracleFactory;
      ContractABI ca;
      bytes code;
      size_t savepoint=-1;
      bytes ThirdPartyFunction;
      bytes symbolFun;
     
    public:
      vector<string> callPayloads;
     
      Address addr;
      TargetExecutive(OracleFactory *oracleFactory, TargetProgram *program, Address addr, ContractABI ca, bytes code) {
        this->code = code;
        this->ca = ca;
        this->addr = addr;
        this->program = program;
        this->oracleFactory = oracleFactory;
      }
      TargetContainerResult exec(bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      TargetContainerResult execAFunction(string functionName,bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis);
      TargetContainerResult execSomeFunction(const vector<string> & functionNames,bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis);
      void symExec();
      void deploy(bytes data, OnOpFunc onOp);
      void setThirdPartyFunction(bytes  selector)
      {
          ThirdPartyFunction=selector;
      }
  };
}
