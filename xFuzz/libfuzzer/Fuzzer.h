#pragma once
#include <iostream>
#include <vector>
#include <liboracle/Common.h>
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum FuzzMode { AFL };
  enum Reporter { TERMINAL, JSON, BOTH };
  struct ContractInfo {
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    string srcmap;
    string srcmapRuntime;
    string source;
    string functionName;
    vector<string> internalCalls;
    vector<string> constantFunctionSrcmap;
    vector<string> reentrancyFunctionSrcmap;
    bool isMain;
    bool isThirdParty = false;
  };
  struct FuzzParam {
    vector<ContractInfo> contractInfo;
    FuzzMode mode;
    Reporter reporter;
    int duration;
    int analyzingInterval;
    string attackerName;
    //string functionName;
    //string internalCall;
    string priority = "111";
    string externalCall;   
  };
  struct FuzzStat {
    int idx = 0;
    uint64_t maxdepth = 0;
    bool clearScreen = false;
    int totalExecs = 0;
    int queueCycle = 0;
    int stageFinds[32];
    double lastNewPath = 0;
    bool isTargetContract = false;
    string mutationstage;
  };
  struct Leader {
    FuzzItem item;
    u256 comparisonValue = 0;
    Leader(FuzzItem _item, u256 _comparisionValue): item(_item) {
      comparisonValue = _comparisionValue;
    }
    
  };
  class Fuzzer {
    vector<double> recordTime;
    vector<bool> vulnerabilities;
    vector<bool> firstVulnerabilitis;
    map<string,vector<bool>> funVulnerabilities ;
    map<string, vector<double>> recordFunTime;
    map<string, string> selector2Name;
    vector<string> queues;
    vector<string> firstQueues;
    unordered_set<string> tracebits;
    unordered_set<string> predicates;
    unordered_map<string, Leader> leaders;
    unordered_map<uint64_t, string> snippets;
    unordered_set<string> uniqExceptions;
    unordered_set<string> uniqPayload;
    vector<string> callPayloads;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    ContractInfo curFuzzContract;
    bytes targetFunctionForThirdParty;
    u32 EXECUTE_RATIO = 10;
    unordered_set<uint64_t> targetJumpis;
    unordered_map<string, bytes> firstStageData;
    unordered_map<string, bytes> secondStageData;
    uint8_t contractCount = 0;

    ///u32 exeProcess=0;
    void writeStats(const Mutation &mutation);
    ContractInfo mainContract();
    public:
      Fuzzer(FuzzParam fuzzParam);
      FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void showStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void updateTracebits(unordered_set<string> tracebits);
      void updatePredicates(unordered_map<string, u256> predicates);
      void updateExceptions(unordered_set<string> uniqExceptions);
      void start();
      void start3Contract();
      void stop();
      void UpdateFirstQueues();
      void setSencondStage();
      void updateTime();
      void updateFunTime(double findTime);
     
      //void fuzzloop();

  };
}
