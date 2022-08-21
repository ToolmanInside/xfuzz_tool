#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <libfuzzer/Fuzzer.h>

using namespace std;
using namespace fuzzer;
using namespace boost::filesystem;
namespace pt = boost::property_tree;
namespace po = boost::program_options;

ContractInfo parseJson(string jsonFile, string contractName, bool isMain) {
  std::ifstream file(jsonFile);
  if (!file.is_open()) {
    stringstream output;
    output << "[x] File " + jsonFile + " is not found" << endl;
    cout << output.str();
    exit(0);
  }
  pt::ptree root;
  pt::read_json(jsonFile, root);
  string fullContractName = "";
  for (auto key : root.get_child("contracts")) {
    if (boost::ends_with(key.first, contractName)) {
      fullContractName = key.first;
      break;
    }
  }
  if (!fullContractName.length()) {
    cout << "[x] No contract " << contractName << endl;
    exit(0);
  }

  //cout<<"LOOK1 !\n";
  pt::ptree::path_type abiPath("contracts|"+ fullContractName +"|abi", '|');
  pt::ptree::path_type binPath("contracts|"+ fullContractName +"|bin", '|');
  pt::ptree::path_type binRuntimePath("contracts|" + fullContractName + "|bin-runtime", '|');
  pt::ptree::path_type srcmapPath("contracts|" + fullContractName + "|srcmap", '|');
  pt::ptree::path_type srcmapRuntimePath("contracts|" + fullContractName + "|srcmap-runtime", '|');
  //cout<<"LOOK2 !\n";
  ContractInfo contractInfo;
  contractInfo.isMain = isMain;
  contractInfo.abiJson = root.get<string>(abiPath);
  contractInfo.bin = root.get<string>(binPath);
  contractInfo.binRuntime = root.get<string>(binRuntimePath);
  contractInfo.srcmap = root.get<string>(srcmapPath);
  contractInfo.srcmapRuntime = root.get<string>(srcmapRuntimePath);
  contractInfo.contractName = fullContractName;
  
  for (auto it : root.get_child("sources")) {
    auto ast = it.second.get_child("AST");
    vector<pt::ptree> stack = {ast};
    while (stack.size() > 0) {
      auto item = stack[stack.size() - 1];
      stack.pop_back();
      if (item.get<string>("name") == "FunctionDefinition") {
        if (item.get<bool>("attributes.constant")) {
          contractInfo.constantFunctionSrcmap.push_back(item.get<string>("src"));
        }
      }
      if (item.get_child_optional("children")) {
        for (auto it : item.get_child("children")) {
          stack.push_back(it.second);
        }
      }
    }
  }

/////added by zhang




  //cout<<"LOOK3  \n";
  return contractInfo;
}



ContractInfo parseJson(string jsonFile, string contractName,string functionname,vector<string> internalCalls ,bool isMain) {
  std::ifstream file(jsonFile);
  if (!file.is_open()) {
    stringstream output;
    output << "[x] File " + jsonFile + " is not found" << endl;
    cout << output.str();
    exit(0);
  }
  pt::ptree root;
  pt::read_json(jsonFile, root);
  string fullContractName = "";
  for (auto key : root.get_child("contracts")) {
    if (boost::ends_with(key.first, contractName)) {
      fullContractName = key.first;
      break;
    }
  }
  if (!fullContractName.length()) {
    cout << "[x] No contract " << contractName << endl;
    exit(0);
  }

  //cout<<"LOOK1 !\n";
  pt::ptree::path_type abiPath("contracts|"+ fullContractName +"|abi", '|');
  pt::ptree::path_type binPath("contracts|"+ fullContractName +"|bin", '|');
  pt::ptree::path_type binRuntimePath("contracts|" + fullContractName + "|bin-runtime", '|');
  pt::ptree::path_type srcmapPath("contracts|" + fullContractName + "|srcmap", '|');
  pt::ptree::path_type srcmapRuntimePath("contracts|" + fullContractName + "|srcmap-runtime", '|');
  //cout<<"LOOK2 !\n";
  ContractInfo contractInfo;
  contractInfo.isMain = isMain;
  contractInfo.abiJson = root.get<string>(abiPath);
  contractInfo.bin = root.get<string>(binPath);
  contractInfo.binRuntime = root.get<string>(binRuntimePath);
  contractInfo.srcmap = root.get<string>(srcmapPath);
  contractInfo.srcmapRuntime = root.get<string>(srcmapRuntimePath);
  contractInfo.contractName = fullContractName;
  
  for (auto it : root.get_child("sources")) {
    auto ast = it.second.get_child("AST");
    vector<pt::ptree> stack = {ast};
    while (stack.size() > 0) {
      auto item = stack[stack.size() - 1];
      stack.pop_back();
      if (item.get<string>("name") == "FunctionDefinition") {
        if (item.get<bool>("attributes.constant")) {
          contractInfo.constantFunctionSrcmap.push_back(item.get<string>("src"));
        }
      }
      if (item.get_child_optional("children")) {
        for (auto it : item.get_child("children")) {
          stack.push_back(it.second);
        }
      }
    }
  }

/////added by zhang
    for (auto it : root.get_child("sources")) {
    auto ast = it.second.get_child("AST");
    vector<pt::ptree> stack = {ast};
    while (stack.size() > 0) {
      auto item = stack[stack.size() - 1];
      stack.pop_back();
      if (item.get<string>("name") == "FunctionDefinition") {
        auto tempFunctionName=item.get<string>("attributes.name");
       
        auto isInternalCall= find(internalCalls.begin(),internalCalls.end(),tempFunctionName)!=internalCalls.end();
        //cout<<internalCalls[0]<<endl;
        //if(isInternalCall) cout<<"internalCalls[0]:  "<<internalCalls[0]<<endl;
        if (tempFunctionName == functionname || isInternalCall ) {
          // cout<<"tempFunctionName:  "<<tempFunctionName<<"   "<<item.get<string>("src")<<endl;
          contractInfo.reentrancyFunctionSrcmap.push_back(item.get<string>("src"));
        }
      }
      if (item.get_child_optional("children")) {
        for (auto it : item.get_child("children")) {
          stack.push_back(it.second);
        }
      }
    }
  }


  //added by zhang in Utils.h
  //for( auto iter : contractInfo.reentrancyFunctionSrcmap) cout<<iter<<endl;
    
  



  return contractInfo;
}

ContractInfo parseSource(string sourceFile, string jsonFile, string contractName,string functionName, string internalCall,bool isMain) {
  std::ifstream file(sourceFile);
  if (!file.is_open()) {
    stringstream output;
    output << "[x] File " + jsonFile + " is not found" << endl;
    cout << output.str();
    exit(0);
  }
  vector<string> internalCalls;
  //internalCalls.push_back(internalCall);
  if(!internalCall.empty())  internalCalls = splitString(internalCall,'+');
  
  auto contractInfo = parseJson(jsonFile, contractName, functionName,internalCalls,isMain);
  std::string sourceContent((std::istreambuf_iterator<char>(file)),(std::istreambuf_iterator<char>()));
  contractInfo.source = sourceContent;
  contractInfo.functionName = functionName;
  contractInfo.internalCalls=internalCalls;
  //cout<<"contractInfo.internalCalls  "<<internalCalls.size()<<endl;

  return contractInfo;
}


ContractInfo parseSource(string sourceFile, string jsonFile, string externalCall,bool isThirdParty)
{
  //cout<<externalCall<<endl;
   std::ifstream file(sourceFile);
  if (!file.is_open()) {
    stringstream output;
    output << "[x] File " + jsonFile + " is not found" << endl;
    cout << output.str();
    exit(0);
  }
  auto pos_=externalCall.find('_');
  string  contractName;
  string  functionName;
  if(pos_ != externalCall.npos)
  {

    contractName=externalCall.substr(0,pos_);
    functionName=externalCall.substr(pos_+1,externalCall.size());
    ///cout<<"externalCall:   "<<contractName<<"  "<<functionName<<endl;

  }
  vector<string> tp;
 
  auto contractInfo = parseJson(jsonFile, contractName,functionName, tp , false);
  std::string sourceContent((std::istreambuf_iterator<char>(file)),(std::istreambuf_iterator<char>()));
  contractInfo.source = sourceContent;
  contractInfo.isThirdParty=true;
  contractInfo.functionName = functionName;
  contractInfo.internalCalls=tp;
  return contractInfo;

}

string toContractName(directory_entry file) {
  string filePath = file.path().string();
  string fileName = file.path().filename().string();
  string fileNameWithoutExtension = fileName.find(".") != string::npos
  ? fileName.substr(0, fileName.find("."))
  : fileName;
  string contractName = fileNameWithoutExtension.find("_0x") != string::npos
  ? fileNameWithoutExtension.substr(0, fileNameWithoutExtension.find("_0x"))
  : fileNameWithoutExtension;
  return contractName;
}

void forEachFile(string folder, string extension, function<void (directory_entry)> cb) {
  path folderPath(folder);
  for (auto& file : boost::make_iterator_range(directory_iterator(folderPath), {})) {
    if (is_directory(file.status())) forEachFile(file.path().string(), extension, cb);
    if (!is_directory(file.status()) && boost::ends_with(file.path().string(), extension)) cb(file);
  }
}

string compileSolFiles(string folder) {
  stringstream ret;
  forEachFile(folder, ".sol", [&](directory_entry file) {
    string filePath = file.path().string();
    ret << "solc";
    ret << " --combined-json abi,bin,bin-runtime,srcmap,srcmap-runtime,ast " + filePath;
    ret << " > " + filePath + ".json";
    ret << endl;
  });
  return ret.str();
}

string fuzzJsonFiles(string contracts, string assets, int duration, int mode, int reporter, string attackerName) {
  stringstream ret;
  unordered_set<string> contractNames;
  /* search for sol file */
  forEachFile(contracts, ".sol", [&](directory_entry file) {
    auto filePath = file.path().string();
    auto contractName = toContractName(file);
    if (contractNames.count(contractName)) return;
    ret << "./fuzzer";
    ret << " --file " + filePath + ".json";
    ret << " --source " + filePath;
    ret << " --name " + contractName;
    ret << " --assets " + assets;
    ret << " --duration " + to_string(duration);
    ret << " --mode " + to_string(mode);
    ret << " --reporter " + to_string(reporter);
    ret << " --attacker " + attackerName;
    ret << endl;
  });
  return ret.str();
}


vector<ContractInfo> parseAssets(string assets) {
  vector<ContractInfo> ls;
  forEachFile(assets, ".json", [&](directory_entry file) {
    auto contractName = toContractName(file);
    auto jsonFile = file.path().string();
    ls.push_back(parseJson(jsonFile, contractName, false));
  });
  return ls;
}

void showHelp(po::options_description desc) {
  stringstream output;
  output << desc << endl;
  output << "Example:" << endl;
  output << "> Generate executable scripts" << endl;
  output << "  " cGRN "./fuzzer -g" cRST << endl;
  cout << output.str();
}

void showGenerate() {
  stringstream output;
  output << cGRN "> Created \"fuzzMe\"" cRST "\n";
  output << cGRN "> To fuzz contracts:" cRST "\n";
  output << "  chmod +x fuzzMe\n";
  output << "  ./fuzzMe\n";
  cout << output.str();
}
