#include <math.h>
#include "TargetContainer.h"
#include "Util.h"
#include "ContractABI.h"
#include <boost/multiprecision/cpp_dec_float.hpp>

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
using namespace boost::multiprecision;

namespace fuzzer {
  TargetContainer::TargetContainer() {
    program = new TargetProgram();
    oracleFactory = new OracleFactory();
    baseAddress = ATTACKER_ADDRESS;
  }

  TargetExecutive TargetContainer::loadContract(bytes code, ContractABI ca) {
    //cout<<"baseAddress:   "<<baseAddress<<endl;
    if (baseAddress > CONTRACT_ADDRESS + 1) {
      cout << "> Currently does not allow to load more than 2 asset contract" << endl;
      exit(0);
    }
    Address addr(baseAddress);
    TargetExecutive te(oracleFactory, program, addr, ca, code);
    baseAddress ++;
    return te;
  }

  TargetExecutive TargetContainer::loadMainContract(bytes code, ContractABI ca) {
    /*
    cout<<"baseAddress:   "<<baseAddress<<endl;
    if (baseAddress > CONTRACT_ADDRESS + 1) {
      cout << "> Currently does not allow to load more than 2 asset contract" << endl;
      exit(0);
    }
    */
    Address addr(u160(0xf2));
    TargetExecutive te(oracleFactory, program, addr, ca, code);
    //baseAddress ++;
    return te;
  }

  TargetContainer::~TargetContainer() {
    delete program;
    delete oracleFactory;
  }
}
