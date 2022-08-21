#include <iostream>
#include <libfuzzer/Fuzzer.h>
#include "Utils.h"

using namespace std;
using namespace fuzzer;

static int DEFAULT_MODE = AFL;
static int DEFAULT_DURATION = 120; // 2 mins
static int DEFAULT_REPORTER = JSON;
static int DEFAULT_ANALYZING_INTERVAL = 1; // 1 sec
static string DEFAULT_CONTRACTS_FOLDER = "contracts/";
static string DEFAULT_ASSETS_FOLDER = "assets/";
static string DEFAULT_ATTACKER = "ReentrancyAttacker";

int main(int argc, char* argv[]) {
  /* Run EVM silently */
  dev::LoggingOptions logOptions;
  logOptions.verbosity = VerbositySilent;
  dev::setupLogging(logOptions);
  /* Program options */
  int mode = DEFAULT_MODE;
  int duration = DEFAULT_DURATION;
  int reporter = DEFAULT_REPORTER;
  string contractsFolder = DEFAULT_CONTRACTS_FOLDER;
  string assetsFolder = DEFAULT_ASSETS_FOLDER;
  
  string jsonFile = "";
  string contractName = "";
  string functionName = "";
  string externalCall = "";
  string internalCall = "";
  string sourceFile = "";
  string priority = "";
  string attackerName = DEFAULT_ATTACKER;
  po::options_description desc("Allowed options");
  po::variables_map vm;
  
  desc.add_options()
    ("help,h", "produce help message")
    ("contracts,c", po::value(&contractsFolder), "contract's folder path")
    ("generate,g", "fuzzMe script")
    ("assets,a", po::value(&assetsFolder), "asset's folder path")
    ("file,f", po::value(&jsonFile), "fuzz a contract")
    ("name,n", po::value(&contractName), "contract name")
    ("function,N", po::value(&functionName), "function name")
    ("internalcall,I", po::value(&internalCall), "function name")
    ("externalcall,E", po::value(&externalCall), "function name")
    ("priority,p",po::value(&priority), "path priority")
    ("source,s", po::value(&sourceFile), "source file path")
    ("mode,m", po::value(&mode), "choose mode: 0 - AFL ")
    ("reporter,r", po::value(&reporter), "choose reporter: 0 - TERMINAL | 1 - JSON")
    ("duration,d", po::value(&duration), "fuzz duration")
    ("attacker", po::value(&attackerName), "choose attacker: NormalAttacker | ReentrancyAttacker");
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);
  /* Show help message */
  if (vm.count("help")) showHelp(desc);
  /* Generate working scripts */
  if (vm.count("generate")) {
    std::ofstream fuzzMe("fuzzMe");
    fuzzMe << "#!/bin/bash" << endl;
    fuzzMe << compileSolFiles(contractsFolder);
    fuzzMe << compileSolFiles(assetsFolder);
    fuzzMe << fuzzJsonFiles(contractsFolder, assetsFolder, duration, mode, reporter, attackerName);
    fuzzMe.close();
    showGenerate();
    return 0;
  }
/*
  if(vm.count("function"))
  {
    cout<<vm["function"].as<std::string>() << std::endl;
    return 0;
  }
*/
  // cout<<functionName<<endl; return 0;
  /* Fuzz a single contract */
  if (vm.count("file") && vm.count("name") && vm.count("source")) {
    FuzzParam fuzzParam;
    auto contractInfo = parseAssets(assetsFolder);
    //record external contract
    if( externalCall.size()>0 )   contractInfo.push_back(parseSource(sourceFile, jsonFile, externalCall,true));
    //record tested contract's function names
    contractInfo.push_back(parseSource(sourceFile, jsonFile, contractName,functionName, internalCall,true));

    fuzzParam.contractInfo = contractInfo;
    fuzzParam.mode = (FuzzMode) mode;
    fuzzParam.duration = duration;
    fuzzParam.reporter = (Reporter) reporter;
    fuzzParam.analyzingInterval = DEFAULT_ANALYZING_INTERVAL;
    fuzzParam.attackerName = attackerName;
    fuzzParam.priority = priority;
    fuzzParam.externalCall = externalCall;

    Fuzzer fuzzer(fuzzParam);
    cout << ">> Fuzz " << contractName << endl;
    // cout<<"externalCall:   "<<externalCall;
    // cout<<"   internalCall:   "<<internalCall<<endl;
    //fuzzer.start3Contract();
    //std::remove("debug.txt");
    //std::remove("info.txt");
    if(!externalCall.empty()) fuzzer.start3Contract();
    else fuzzer.start();
    
    //fuzzer.start();
    return 0;
  }
  return 0;
}
