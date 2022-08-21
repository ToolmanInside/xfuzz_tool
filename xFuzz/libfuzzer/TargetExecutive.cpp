#include "TargetExecutive.h"
#include "Logger.h"
#include <map>

namespace fuzzer
{
  void TargetExecutive::deploy(bytes data, OnOpFunc onOp)
  {
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
  }


  TargetContainerResult TargetExecutive::exec(bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis)
  {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    RecordParam recordParam;
    u256 lastCompValue = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    unordered_set<string> uniqExceptions;
    unordered_set<string> tracebits;
    unordered_map<string, u256> predicates;
    vector<bytes> outputs;
    bool isReach = false;
    string reachData;

    if (savepoint != -1)
      program->rollback(savepoint);
    savepoint = program->savepoint();
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const *_vm, ExtVMFace const *ext) {
      auto vm = dynamic_cast<LegacyVM const *>(_vm);
      // cout<<hex;
      //cout<<"pc  "<<pc<<"  inst:  "<<(int)inst<<endl;
      //cout<<"stack size: " <<vm->stack().size()<<endl;;
      /* Oracle analyze data */
      switch (inst)
      {
      case Instruction::CALL:
      case Instruction::CALLCODE:
      case Instruction::DELEGATECALL:
      case Instruction::STATICCALL:
      {
        vector<u256>::size_type stackSize = vm->stack().size();
        u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;
        auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);
        auto inOff = (uint64_t)vm->stack()[sizeOffset];
        auto inSize = (uint64_t)vm->stack()[sizeOffset - 1];
        auto first = vm->memory().begin();
        OpcodePayload payload;
        payload.caller = ext->myAddress;
        payload.callee = Address((u160)vm->stack()[stackSize - 2]);
        payload.pc = pc;
        payload.gas = vm->stack()[stackSize - 1];
        payload.wei = wei;
        payload.inst = inst;
        payload.data = bytes(first + inOff, first + inOff + inSize);
        oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
        if (inSize >= 4)
        {
          bytes temp(payload.data.begin(), payload.data.begin() + 4);
          //cout<<"payload.data:   "<<payload.data<<"  ThirdPartyFunction：        "<<ThirdPartyFunction<<endl;
          if (temp == ThirdPartyFunction)
          {
            // cout<<" CALL PAYLOAD:  "<<temp<<endl;
            isReach = true;
          }
        }
        break;
      }
      case Instruction::ORIGIN:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        oracleFactory->save(OpcodeContext(ext->depth, payload));
        break;
      }

      case Instruction::SSTORE:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        oracleFactory->save(OpcodeContext(ext->depth, payload));
        break;
      }

      default:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        if (
            inst == Instruction::SUICIDE ||
            inst == Instruction::NUMBER ||
            inst == Instruction::TIMESTAMP ||
            inst == Instruction::INVALID ||
            inst == Instruction::ADD ||
            inst == Instruction::SUB)
        {
          vector<u256>::size_type stackSize = vm->stack().size();
          if (inst == Instruction::ADD || inst == Instruction::SUB)
          {
            auto left = vm->stack()[stackSize - 1];
            auto right = vm->stack()[stackSize - 2];
            if (inst == Instruction::ADD)
            {
              auto total256 = left + right;
              auto total512 = (u512)left + (u512)right;
              payload.isOverflow = total512 != total256;
            }
            if (inst == Instruction::SUB)
            {
              payload.isUnderflow = left < right;
            }
          }
          oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
        }
        break;
      }
      }
      /* Mutation analyzes data */
      switch (inst)
      {
      case Instruction::GT:
      case Instruction::SGT:
      case Instruction::LT:
      case Instruction::SLT:
      case Instruction::EQ:
      {
        vector<u256>::size_type stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          u256 left = vm->stack()[stackSize - 1];
          u256 right = vm->stack()[stackSize - 2];
          /* calculate if command inside a function */
          u256 temp = left > right ? left - right : right - left;

          /// added by zhang   count the bit diff
          /* auto  BitCount = [](u256 n) -> uint
            {
              unsigned int c =0 ; 
              while (n >0)
              {
                if((n &1) ==1)  ++c ;                 
                  n >>=1 ; 
              }
              return c ;
            };
            temp=BitCount(temp);
            */

          lastCompValue = temp + 1;
        }
        break;
      }
      default:
      {
        break;
      }
      }
      /* Calculate left and right branches for valid jumpis*/
      auto recordable = recordParam.isDeployment && get<0>(validJumpis).count(pc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(pc);
      if (inst == Instruction::JUMPCI && recordable)
      {
        jumpDest1 = (u64)vm->stack().back();
        jumpDest2 = pc + 1;
      }
      /* Calculate actual jumpdest and add reverse branch to predicate */
      recordable = recordParam.isDeployment && get<0>(validJumpis).count(recordParam.lastpc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(recordParam.lastpc);
      if (prevInst == Instruction::JUMPCI && recordable)
      {
        auto branchId = to_string(recordParam.lastpc) + ":" + to_string(pc);
        ///added by zhang
        ///cout<<branchId<<endl;
        tracebits.insert(branchId);
        /* Calculate branch distance */
        u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
        branchId = to_string(recordParam.lastpc) + ":" + to_string(jumpDest);
        predicates[branchId] = lastCompValue;
      }
      prevInst = inst;
      recordParam.lastpc = pc;
    };
    /* Decode and call functions */
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();
    //for( auto iter : funcs) cout<<iter<<endl;
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    /* Record all JUMPI in constructor */
    recordParam.isDeployment = true;
    auto sender = ca.getSender();
    OpcodePayload payload;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(OpcodeContext(0, payload));
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
    if (res.excepted != TransactionException::None)
    {
      auto exceptionId = to_string(recordParam.lastpc);
      uniqExceptions.insert(exceptionId);
      /* Save Call Log */
      OpcodePayload payload;
      payload.inst = Instruction::INVALID;
      oracleFactory->save(OpcodeContext(0, payload));
    }
    oracleFactory->finalize();

    bytes temp;

    vector<int> v;
    for( int i=0; i<funcs.size(); i++) v.push_back(i);
    unsigned seed = std::chrono::system_clock::now ().time_since_epoch().count();
    std::shuffle (v.begin (), v.end (), std::default_random_engine (seed));
    for (uint32_t funcIdx : v)
    {
      /* Update payload */
      bytes func = funcs[funcIdx];
      auto fd = ca.fds[funcIdx];
      if (fd.name == "")
        continue;
      // cout<<"new function: "<<fd.name<<endl;

      if (isReach)
      {
        reachData = toHex(temp);
        isReach = false;
      }
      temp = func;

      // replace the origin payload
      if (!callPayloads.empty())
      {
        bytes selector1(func.begin(), func.begin() + 4);
        bytes selector2(callPayloads[0].begin(), callPayloads[0].begin() + 4);
        if (selector1 == selector2)
        {
          auto tempPoint = program->savepoint();
          for (auto iter : callPayloads)
          {
            func = fromHex(iter);
            /* Ignore JUMPI until program reaches inside function */
            recordParam.isDeployment = false;
            OpcodePayload payload;
            payload.data = func;
            payload.inst = Instruction::CALL;
            payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
            payload.caller = sender;
            payload.callee = addr;
            payload.isTargetFunction = true;
            oracleFactory->save(OpcodeContext(0, payload));
            res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
            outputs.push_back(res.output);
            if (res.excepted != TransactionException::None)
            {
              auto exceptionId = to_string(recordParam.lastpc);
              uniqExceptions.insert(exceptionId);
              /* Save Call Log */
              OpcodePayload payload;
              payload.inst = Instruction::INVALID;
              oracleFactory->save(OpcodeContext(0, payload));
            }
            oracleFactory->finalize();
          }
          program->rollback(tempPoint);
        }
      }

      //cout<<fd.name<<"   "<<func<<endl;;

      //cout<<bytes(5,5)<<endl;

      /*
      if(fd.hasreentrancy){
        cout<<funcIdx<<endl;
        cout<<fd.name<<endl;
      }
      */

      /* Ignore JUMPI until program reaches inside function */
      recordParam.isDeployment = false;
      OpcodePayload payload;
      payload.data = func;
      payload.inst = Instruction::CALL;
      payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
      payload.caller = sender;
      payload.callee = addr;
      
      payload.isTargetFunction = fd.name == ca.getReentrancyfunction();
      // if( payload.isTargetFunction ) cout<<fd.name<<endl;
      payload.isExternalCall = isReach;
      oracleFactory->save(OpcodeContext(0, payload));
      res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
      outputs.push_back(res.output);

      if (res.excepted != TransactionException::None)
      {
        auto exceptionId = to_string(recordParam.lastpc);
        uniqExceptions.insert(exceptionId);
        /* Save Call Log */
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
      }
      oracleFactory->finalize();
    }

    if (isReach)
    {
      reachData = toHex(funcs.back());
      isReach = false;
    }
    /* Reset data before running new contract */
    string cksum = "";
    for (auto t : tracebits)
      cksum = cksum + t;

    /*
    u64 temp=0;
    for( auto iter : predicates ) temp+=(u64)iter.second;
    cksum=to_string(predicates.size())+to_string(temp);
    */
    return TargetContainerResult(tracebits, predicates, uniqExceptions, cksum, reachData);
  }

  TargetContainerResult TargetExecutive::execAFunction(string functionName, bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis)
  {
    /* Save all hit branches to trace_bits */

    Instruction prevInst;
    RecordParam recordParam;
    u256 lastCompValue = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    unordered_set<string> uniqExceptions;
    unordered_set<string> tracebits;
    unordered_map<string, u256> predicates;
    vector<bytes> outputs;
    bool isReach = false;
    string reachData;

    //bool debugFlag = false;

    size_t aFunctionsavepoint = program->savepoint();
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const *_vm, ExtVMFace const *ext) {
      //if(pc >= 0x806 || debugFlag )
      //cout<<hex<<pc<<endl;

      auto vm = dynamic_cast<LegacyVM const *>(_vm);

      /* Oracle analyze data */
      switch (inst)
      {
      case Instruction::CALL:
      case Instruction::CALLCODE:
      case Instruction::DELEGATECALL:
      case Instruction::STATICCALL:
      {
        vector<u256>::size_type stackSize = vm->stack().size();
        u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;
        auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);
        auto inOff = (uint64_t)vm->stack()[sizeOffset];
        auto inSize = (uint64_t)vm->stack()[sizeOffset - 1];
        auto first = vm->memory().begin();
        OpcodePayload payload;
        payload.caller = ext->myAddress;
        payload.callee = Address((u160)vm->stack()[stackSize - 2]);
        payload.pc = pc;
        payload.gas = vm->stack()[stackSize - 1];
        payload.wei = wei;
        payload.inst = inst;
        payload.data = bytes(first + inOff, first + inOff + inSize);
        oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
        // cout<<ext->depth + 1<<endl;
        // cout<<payload.caller<<"  " <<payload.callee<<"   "<<payload.data<<endl;

        if (inSize >= 4)
        {
          bytes temp(payload.data.begin(), payload.data.begin() + 4);
          //cout<<"payload.data:   "<<payload.data<<"  ThirdPartyFunction：        "<<ThirdPartyFunction<<endl;
          //debugFlag=true;
          //cout<<"payload.caller:  "<<payload.caller<<"  payload.callee:"<<payload.callee<<endl;
          if (payload.callee != payload.caller && temp == ThirdPartyFunction)
          {
            //cout<<" CALL PAYLOAD:  "<<temp<<endl;
            reachData = toHex(payload.data);
            isReach = true;
            //exit(1);
          }
        }

        break;
      }
      case Instruction::ORIGIN:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        oracleFactory->save(OpcodeContext(ext->depth, payload));
        break;
      }
      case Instruction::SSTORE:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        oracleFactory->save(OpcodeContext(ext->depth, payload));
        break;
      }
      default:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        if (
            inst == Instruction::SUICIDE ||
            inst == Instruction::NUMBER ||
            inst == Instruction::TIMESTAMP ||
            inst == Instruction::INVALID ||
            inst == Instruction::ADD ||
            inst == Instruction::SUB)
        {
          vector<u256>::size_type stackSize = vm->stack().size();
          if (inst == Instruction::ADD || inst == Instruction::SUB)
          {
            auto left = vm->stack()[stackSize - 1];
            auto right = vm->stack()[stackSize - 2];
            if (inst == Instruction::ADD)
            {
              auto total256 = left + right;
              auto total512 = (u512)left + (u512)right;
              payload.isOverflow = total512 != total256;
            }
            if (inst == Instruction::SUB)
            {
              payload.isUnderflow = left < right;
            }
          }
          oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
        }
        break;
      }
      }
      /* Mutation analyzes data */
      switch (inst)
      {
      case Instruction::GT:
      case Instruction::SGT:
      case Instruction::LT:
      case Instruction::SLT:
      case Instruction::EQ:
      {
        vector<u256>::size_type stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          u256 left = vm->stack()[stackSize - 1];
          u256 right = vm->stack()[stackSize - 2];
          /* calculate if command inside a function */
          u256 temp = left > right ? left - right : right - left;

          lastCompValue = temp + 1;
        }
        break;
      }
      default:
      {
        break;
      }
      }
      /* Calculate left and right branches for valid jumpis*/
      auto recordable = recordParam.isDeployment && get<0>(validJumpis).count(pc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(pc);
      if (inst == Instruction::JUMPCI && recordable)
      {
        jumpDest1 = (u64)vm->stack().back();
        jumpDest2 = pc + 1;
      }
      /* Calculate actual jumpdest and add reverse branch to predicate */
      recordable = recordParam.isDeployment && get<0>(validJumpis).count(recordParam.lastpc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(recordParam.lastpc);
      if (prevInst == Instruction::JUMPCI && recordable)
      {
        auto branchId = to_string(recordParam.lastpc) + ":" + to_string(pc);
        ///added by zhang
        ///cout<<branchId<<endl;
        tracebits.insert(branchId);
        /* Calculate branch distance */
        u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
        branchId = to_string(recordParam.lastpc) + ":" + to_string(jumpDest);
        predicates[branchId] = lastCompValue;
      }
      prevInst = inst;
      recordParam.lastpc = pc;
    };
    /* Decode and call functions */
    ca.updateTestData(data);

    vector<bytes> funcs = ca.encodeFunctions();

    auto sender = ca.getSender();
    bytes temp;
    unordered_set<string> reachDataRefer;
    for (uint32_t funcIdx = 0; funcIdx < funcs.size(); funcIdx++)
    {
      /* Update payload */
      bytes func = funcs[funcIdx];
      auto fd = ca.fds[funcIdx];
      if (fd.name != functionName)
        continue;

      temp = func;

      // replace origin payload with have produced
      if (!callPayloads.empty())
      {
        bytes selector1(func.begin(), func.begin() + 4);
        bytes selector2(callPayloads[0].begin(), callPayloads[0].begin() + 4);
        if (selector1 == selector2)
        {
          auto tempPoint = program->savepoint();
          for (auto iter : callPayloads)
          {
            func = fromHex(iter);
            /* Ignore JUMPI until program reaches inside function */
            recordParam.isDeployment = false;
            OpcodePayload payload;
            payload.data = func;
            payload.inst = Instruction::CALL;
            payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
            payload.caller = sender;
            payload.callee = addr;
            oracleFactory->save(OpcodeContext(0, payload));
            auto res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
            outputs.push_back(res.output);
            if (res.excepted != TransactionException::None)
            {
              auto exceptionId = to_string(recordParam.lastpc);
              uniqExceptions.insert(exceptionId);
              /* Save Call Log */
              OpcodePayload payload;
              payload.inst = Instruction::INVALID;
              oracleFactory->save(OpcodeContext(0, payload));
            }
            oracleFactory->finalize();
          }
          program->rollback(tempPoint);
        }
      }

      // twice call  and have the same callpayload
      for (int i = 0; i < 2; i++)
      {
        /* Ignore JUMPI until program reaches inside function */
        recordParam.isDeployment = false;
        OpcodePayload payload;
        payload.data = func;
        payload.inst = Instruction::CALL;
        payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
        payload.caller = sender;
        payload.callee = addr;
        payload.isExternalCall = true;
        oracleFactory->save(OpcodeContext(0, payload));
        auto res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
        outputs.push_back(res.output);
        if (res.excepted != TransactionException::None)
        {
          auto exceptionId = to_string(recordParam.lastpc);
          uniqExceptions.insert(exceptionId);
          /* Save Call Log */
          OpcodePayload payload;
          payload.inst = Instruction::INVALID;
          oracleFactory->save(OpcodeContext(0, payload));
        }
        oracleFactory->finalize();

        if (isReach && !reachData.empty())
        {
          if (!reachDataRefer.count(reachData))
          {
            reachDataRefer.insert(reachData);
          }
          else
          {
            oracleFactory->save(OpcodeContext(0, payload, reachDataRefer.size() + 1));
            oracleFactory->finalize();
          }
          isReach = false; // reachData.clear();
        }
      }
    }

    /* Reset data before running new contract */
    program->rollback(aFunctionsavepoint);
    string cksum = "";
    for (auto t : tracebits)
      cksum = cksum + t;

    /*
    u64 temp=0;
    for( auto iter : predicates ) temp+=(u64)iter.second;
    cksum=to_string(predicates.size())+to_string(temp);
    */

    return TargetContainerResult(tracebits, predicates, uniqExceptions, cksum, reachData);
  }

  TargetContainerResult TargetExecutive::execSomeFunction(const vector<string> &functionNames, bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis)
  {
    /* Save all hit branches to trace_bits */
    Instruction prevInst;
    RecordParam recordParam;
    u256 lastCompValue = 0;
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    unordered_set<string> uniqExceptions;
    unordered_set<string> tracebits;
    unordered_map<string, u256> predicates;
    vector<bytes> outputs;
    bool isReach = false;
    string reachData;
    size_t aFunctionsavepoint = program->savepoint();
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const *_vm, ExtVMFace const *ext) {
      auto vm = dynamic_cast<LegacyVM const *>(_vm);

      /* Oracle analyze data */
      switch (inst)
      {
      case Instruction::CALL:
      case Instruction::CALLCODE:
      case Instruction::DELEGATECALL:
      case Instruction::STATICCALL:
      {
        vector<u256>::size_type stackSize = vm->stack().size();
        u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;
        auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);
        auto inOff = (uint64_t)vm->stack()[sizeOffset];
        auto inSize = (uint64_t)vm->stack()[sizeOffset - 1];
        auto first = vm->memory().begin();
        OpcodePayload payload;
        payload.caller = ext->myAddress;
        payload.callee = Address((u160)vm->stack()[stackSize - 2]);
        payload.pc = pc;
        payload.gas = vm->stack()[stackSize - 1];
        payload.wei = wei;
        payload.inst = inst;
        payload.data = bytes(first + inOff, first + inOff + inSize);
        oracleFactory->save(OpcodeContext(ext->depth + 1, payload));

        break;
      }
      case Instruction::ORIGIN:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        oracleFactory->save(OpcodeContext(ext->depth, payload));
        break;
      }
      case Instruction::SSTORE:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        oracleFactory->save(OpcodeContext(ext->depth, payload));
        break;
      }
      default:
      {
        OpcodePayload payload;
        payload.pc = pc;
        payload.inst = inst;
        if (
            inst == Instruction::SUICIDE ||
            inst == Instruction::NUMBER ||
            inst == Instruction::TIMESTAMP ||
            inst == Instruction::INVALID ||
            inst == Instruction::ADD ||
            inst == Instruction::SUB)
        {
          vector<u256>::size_type stackSize = vm->stack().size();
          if (inst == Instruction::ADD || inst == Instruction::SUB)
          {
            auto left = vm->stack()[stackSize - 1];
            auto right = vm->stack()[stackSize - 2];
            if (inst == Instruction::ADD)
            {
              auto total256 = left + right;
              auto total512 = (u512)left + (u512)right;
              payload.isOverflow = total512 != total256;
            }
            if (inst == Instruction::SUB)
            {
              payload.isUnderflow = left < right;
            }
          }
          oracleFactory->save(OpcodeContext(ext->depth + 1, payload));
        }
        break;
      }
      }
      /* Mutation analyzes data */
      switch (inst)
      {
      case Instruction::GT:
      case Instruction::SGT:
      case Instruction::LT:
      case Instruction::SLT:
      case Instruction::EQ:
      {
        vector<u256>::size_type stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          u256 left = vm->stack()[stackSize - 1];
          u256 right = vm->stack()[stackSize - 2];
          /* calculate if command inside a function */
          u256 temp = left > right ? left - right : right - left;

          lastCompValue = temp + 1;
        }
        break;
      }
      default:
      {
        break;
      }
      }
      /* Calculate left and right branches for valid jumpis*/
      auto recordable = recordParam.isDeployment && get<0>(validJumpis).count(pc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(pc);
      if (inst == Instruction::JUMPCI && recordable)
      {
        jumpDest1 = (u64)vm->stack().back();
        jumpDest2 = pc + 1;
      }
      /* Calculate actual jumpdest and add reverse branch to predicate */
      recordable = recordParam.isDeployment && get<0>(validJumpis).count(recordParam.lastpc);
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(recordParam.lastpc);
      if (prevInst == Instruction::JUMPCI && recordable)
      {
        auto branchId = to_string(recordParam.lastpc) + ":" + to_string(pc);
        ///added by zhang
        ///cout<<branchId<<endl;
        tracebits.insert(branchId);
        /* Calculate branch distance */
        u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;
        branchId = to_string(recordParam.lastpc) + ":" + to_string(jumpDest);
        predicates[branchId] = lastCompValue;
      }
      prevInst = inst;
      recordParam.lastpc = pc;
    };
    /* Decode and call functions */
    ca.updateTestData(data);

    vector<bytes> funcs = ca.encodeFunctions();

    /*
    //for( auto iter : funcs) cout<<iter<<endl;


    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();
    /* Record all JUMPI in constructor */
    /*    recordParam.isDeployment = true;
    auto sender = ca.getSender();
    OpcodePayload payload;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;
    payload.caller = sender;
    payload.callee = addr;
    oracleFactory->save(OpcodeContext(0, payload));
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
    if (res.excepted != TransactionException::None) {
      auto exceptionId = to_string(recordParam.lastpc);
      uniqExceptions.insert(exceptionId) ;
      /* Save Call Log */
    /*      OpcodePayload payload;
      payload.inst = Instruction::INVALID;
      oracleFactory->save(OpcodeContext(0, payload));
    }
    oracleFactory->finalize();


*/
    auto sender = ca.getSender();
    bytes temp;
    for (uint32_t funcIdx = 0; funcIdx < funcs.size(); funcIdx++)
    {
      /* Update payload */
      bytes func = funcs[funcIdx];
      auto fd = ca.fds[funcIdx];
      auto tempIter = find(functionNames.begin(), functionNames.end(), fd.name);
      if (tempIter == functionNames.end())
        continue;
      //cout<<*tempIter<<endl;
      symbolFun = func;

      if (isReach)
      {
        reachData = toHex(temp);
        isReach = false;
      }
      // temp = func;

      if (!callPayloads.empty())
      {
        bytes selector1(func.begin(), func.begin() + 4);
        bytes selector2(callPayloads[0].begin(), callPayloads[0].begin() + 4);
        if (selector1 == selector2)
        {
          auto tempPoint = program->savepoint();
          for (auto iter : callPayloads)
          {
            func = fromHex(iter);
            /* Ignore JUMPI until program reaches inside function */
            recordParam.isDeployment = false;
            OpcodePayload payload;
            payload.data = func;
            payload.inst = Instruction::CALL;
            payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
            payload.caller = sender;
            payload.callee = addr;
            oracleFactory->save(OpcodeContext(0, payload));
            auto res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
            outputs.push_back(res.output);
            if (res.excepted != TransactionException::None)
            {
              auto exceptionId = to_string(recordParam.lastpc);
              uniqExceptions.insert(exceptionId);
              /* Save Call Log */
              OpcodePayload payload;
              payload.inst = Instruction::INVALID;
              oracleFactory->save(OpcodeContext(0, payload));
            }
            oracleFactory->finalize();
          }
          program->rollback(tempPoint);
        }
      }

      /* Ignore JUMPI until program reaches inside function */
      recordParam.isDeployment = false;
      OpcodePayload payload;
      payload.data = func;
      payload.inst = Instruction::CALL;
      payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
      payload.caller = sender;
      payload.callee = addr;
      payload.isTargetFunction = fd.name == ca.getReentrancyfunction();
      // if( payload.isTargetFunction ) cout<<fd.name<<endl;
      oracleFactory->save(OpcodeContext(0, payload));
      auto res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
      outputs.push_back(res.output);
      if (res.excepted != TransactionException::None)
      {
        auto exceptionId = to_string(recordParam.lastpc);
        uniqExceptions.insert(exceptionId);
        /* Save Call Log */
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
      }
      oracleFactory->finalize();
    }

    if (isReach)
    {
      reachData = toHex(funcs.back());
      isReach = false;
    }

    /* Reset data before running new contract */
    program->rollback(aFunctionsavepoint);
    string cksum = "";
    for (auto t : tracebits)
      cksum = cksum + t;

    /*
    u64 temp=0;
    for( auto iter : predicates ) temp+=(u64)iter.second;
    cksum=to_string(predicates.size())+to_string(temp);
    */
    return TargetContainerResult(tracebits, predicates, uniqExceptions, cksum, reachData);
  }

  void TargetExecutive::symExec()
  {
    vector<string> recordStacks;
    map<uint, string> registerMemory;

    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const *_vm, ExtVMFace const *ext) {
      auto vm = dynamic_cast<LegacyVM const *>(_vm);

      // cout<<"stack size: "<<vm->stack().size()<<"   recordStackSize:  "<<recordStacks.size()<<endl;

      cout << hex;
      //cout<<"pc:  "<<pc<<"  inst:  "<<(uint)inst<<endl;

      //add "if" "while" in case  executing CALL instruction
      if (vm->stack().size() < recordStacks.size())
      {
        return;
      }

      switch (inst)
      {
      case Instruction::STOP:
      {
        //return ;
        break;
      }
      case Instruction::ADD:
      case Instruction::XADD:
      {
        auto stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          string addRes;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
              recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            string first, second;
            if (recordStacks[stackSize - 1].find("Id_") != string::npos)
            {
              first = recordStacks[stackSize - 1];
            }
            else
              first = vm->stack()[stackSize - 1].str();

            if (recordStacks[stackSize - 2].find("Id_") != string::npos)
            {
              second = recordStacks[stackSize - 2];
            }
            else
              second = vm->stack()[stackSize - 2].str();

            addRes = "(" + first + "+" + second + ")";
          }
          else
          {
            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            u256 res = left + right;
            addRes = (res.str());
          }
          recordStacks.pop_back();
          recordStacks.pop_back();
          recordStacks.push_back(addRes);
        }
        break;
      }

      case Instruction::MUL:
      case Instruction::XMUL:
      {
        auto stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          string mulRes;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
              recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            string first, second;
            if (recordStacks[stackSize - 1].find("Id_") != string::npos)
            {
              first = recordStacks[stackSize - 1];
            }
            else
              first = vm->stack()[stackSize - 1].str();

            if (recordStacks[stackSize - 2].find("Id_") != string::npos)
            {
              second = recordStacks[stackSize - 2];
            }
            else
              second = vm->stack()[stackSize - 2].str();

            mulRes = "(" + first + ")*(" + second + ")";
          }
          else
          {

            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            u256 res = left * right;
            mulRes = res.str();
          }
          recordStacks.pop_back();
          recordStacks.pop_back();
          recordStacks.push_back(mulRes);
        }
        break;
      }

      case Instruction::SUB:
      case Instruction::XSUB:
      {
        auto stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          string subRes;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
              recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            string first, second;
            if (recordStacks[stackSize - 1].find("Id_") != string::npos)
            {
              first = recordStacks[stackSize - 1];
            }
            else
              first = vm->stack()[stackSize - 1].str();

            if (recordStacks[stackSize - 2].find("Id_") != string::npos)
            {
              second = recordStacks[stackSize - 2];
            }
            else
              second = vm->stack()[stackSize - 2].str();
            subRes = "(" + first + ")-(" + second + ")";
          }
          else
          {

            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            u256 res = left - right;
            subRes = res.str();
          }
          recordStacks.pop_back();
          recordStacks.pop_back();
          recordStacks.push_back(subRes);
        }
        break;
      }

      case Instruction::DIV:
      case Instruction::SDIV:
      case Instruction::XSDIV:
      case Instruction::XDIV:
      {
        auto stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          string divRes;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
              recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            string first, second;
            if (recordStacks[stackSize - 1].find("Id_") != string::npos)
            {
              first = recordStacks[stackSize - 1];
            }
            else
              first = vm->stack()[stackSize - 1].str();

            if (recordStacks[stackSize - 2].find("Id_") != string::npos)
            {
              second = recordStacks[stackSize - 2];
            }
            else
              second = vm->stack()[stackSize - 2].str();

            divRes = "(" + first + ")/(" + second + ")";
          }
          else
          {
            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            u256 res = right == 0 ? 0 : left / right;
            divRes = res.str();
          }
          if (vm->stack()[stackSize - 2] == 0)
          {
            divRes = "0";
          }
          recordStacks.pop_back();
          recordStacks.pop_back();
          recordStacks.push_back(divRes);
        }
        break;
      }

      case Instruction::MOD:
      case Instruction::SMOD:
      case Instruction::XMOD:
      case Instruction::XSMOD:
      {
        auto stackSize = vm->stack().size();
        if (stackSize >= 2)
        {
          string modRes;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
              recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            string first, second;
            if (recordStacks[stackSize - 1].find("Id_") != string::npos)
            {
              first = recordStacks[stackSize - 1];
            }
            else
              first = vm->stack()[stackSize - 1].str();

            if (recordStacks[stackSize - 2].find("Id_") != string::npos)
            {
              second = recordStacks[stackSize - 2];
            }
            else
              second = vm->stack()[stackSize - 2].str();
            modRes = "(" + first + ")%(" + second + ")";
          }
          else
          {

            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            u256 res = right == 0 ? 0 : left % right;
            modRes = res.str();
          }
          if (vm->stack()[stackSize - 2] == 0)
          {
            modRes = "0";
          }
          recordStacks.pop_back();
          recordStacks.pop_back();
          recordStacks.push_back(modRes);
        }
        break;
      }

      case Instruction::ADDMOD:
      {
        auto stackSize = vm->stack().size();

        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos ||
            recordStacks[stackSize - 3].find("Id_") != string::npos)
        {
          string first, second, third;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          if (recordStacks[stackSize - 3].find("Id_") != string::npos)
          {
            third = recordStacks[stackSize - 3];
          }
          else
            third = vm->stack()[stackSize - 3].str();

          res = "(" + first + "+" + second + ")" + "%(" + third + ")";
        }
        else
        {
          res = "NONE";
        }
        if (vm->stack()[stackSize - 3] == 0)
        {
          res = "0";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::MULMOD:
      {
        auto stackSize = vm->stack().size();
        auto first = vm->stack()[stackSize - 1];
        auto second = vm->stack()[stackSize - 2];
        auto third = vm->stack()[stackSize - 3];
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos ||
            recordStacks[stackSize - 3].find("Id_") != string::npos)
        {
          string first, second, third;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          if (recordStacks[stackSize - 3].find("Id_") != string::npos)
          {
            third = recordStacks[stackSize - 3];
          }
          else
            third = vm->stack()[stackSize - 3].str();

          res = "(" + string("(") + first + ")" + "*" + "(" + second + ")" + ")" +
                "%(" + third + ")";
        }
        else
        {
          u256 product = first * second;
          u256 tmpMod = third == 0 ? 0 : product % third;
          res = tmpMod.str();
        }
        if (third == 0)
        {
          res = "0";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::EXP:
      {
        auto stackSize = vm->stack().size();
        auto base = vm->stack()[stackSize - 1];
        auto exponent = vm->stack()[stackSize - 2];
        u256 res = 1;
        string strRes;
        strRes = base.str() + "**" + exponent.str();
        for (u256 i = 0; i < exponent; i++)
        {
          res = res * base;
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(strRes);
        break;
      }

      case Instruction::SIGNEXTEND:
      {
        auto stackSize = vm->stack().size();
        auto index = vm->stack()[stackSize - 1];
        auto content = vm->stack()[stackSize - 2];

        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back("NONE");
        break;
      }

      case Instruction::LT:
      case Instruction::SLT:
      case Instruction::XLT:
      case Instruction::XSLT:
      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos)
        {
          string first, second;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          res = "(" + first + ")<(" + second + ")";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);

        break;
      }

      case Instruction::GT:
      case Instruction::SGT:
      case Instruction::XGT:
      case Instruction::XSGT:
      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos)
        {
          string first, second;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          res = "(" + first + ")>(" + second + ")";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::EQ:
      case Instruction::XEQ:
      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos)
        {
          string first, second;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          res = "(" + first + ")==(" + second + ")";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::ISZERO:
      case Instruction::XISZERO:
      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos)
        {
          res = "(" + recordStacks[stackSize - 1] + ")==0";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::AND:
      case Instruction::XAND:
      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos)
        {
          string first, second;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          res = "(" + first + ")&(" + second + ")";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::OR:
      case Instruction::XOOR:

      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos)
        {
          string first, second;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          res = "(" + first + ") | (" + second + ")";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::XOR:
      case Instruction::XXOR:
      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos ||
            recordStacks[stackSize - 2].find("Id_") != string::npos)
        {
          string first, second;
          if (recordStacks[stackSize - 1].find("Id_") != string::npos)
          {
            first = recordStacks[stackSize - 1];
          }
          else
            first = vm->stack()[stackSize - 1].str();

          if (recordStacks[stackSize - 2].find("Id_") != string::npos)
          {
            second = recordStacks[stackSize - 2];
          }
          else
            second = vm->stack()[stackSize - 2].str();
          res = "(" + first + ") XOR (" + second + ")";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::NOT:
      case Instruction::XNOT:
      {
        auto stackSize = vm->stack().size();
        string res;
        if (recordStacks[stackSize - 1].find("Id_") != string::npos)
        {
          res = "~(" + recordStacks[stackSize - 1] + ")";
        }
        else
        {
          res = "NONE";
        }
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }

      case Instruction::BYTE:
      case Instruction::SHR:
      case Instruction::SAR:
      case Instruction::SHL:
      case Instruction::XSHR:
      case Instruction::XSAR:
      case Instruction::XSHL:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back("NONE");
        break;
      }

      case Instruction::SHA3:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.push_back("NONE");
        break;
      }

      case Instruction::ADDRESS:
      {
        recordStacks.push_back("NONE");
        break;
      }
      case Instruction::BALANCE:
      {
        break;
      }
      case Instruction::CALLER:
      case Instruction::ORIGIN:
      case Instruction::CALLVALUE:
      {
        recordStacks.push_back("NONE");
        break;
      }

      case Instruction::CALLDATACOPY:
      {
        auto stackSize = vm->stack().size();
        string res;
        auto destOffset = (uint)vm->stack()[stackSize - 1];
        auto offset = (uint)vm->stack()[stackSize - 2];
        string varName = "Id_" + to_string(offset);
        registerMemory[destOffset] = varName;
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }

      case Instruction::CALLDATALOAD:
      {
        auto stackSize = vm->stack().size();
        string res;
        uint i_th = (uint)vm->stack()[stackSize - 1];
        string varName = "Id_" + to_string(i_th);

        recordStacks.pop_back();

        recordStacks.push_back(varName);
        break;
      }

      case Instruction::CALLDATASIZE:
      {
        string varName = "Id_len";
        recordStacks.push_back(varName);
        break;
      }
      case Instruction::CODECOPY:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::GASPRICE:
      {
        recordStacks.push_back("NONE");
        break;
      }

      case Instruction::EXTCODESIZE:
      {
        break;
      }
      case Instruction::EXTCODECOPY:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::RETURNDATASIZE:
      {
        recordStacks.push_back("NONE");
        break;
      }
      case Instruction::RETURNDATACOPY:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::EXTCODEHASH:
      case Instruction::BLOCKHASH:
      {
        break;
      }

      case Instruction::COINBASE:
      case Instruction::TIMESTAMP:
      case Instruction::NUMBER:
      case Instruction::DIFFICULTY:
      case Instruction::GASLIMIT:
      {
        recordStacks.push_back("NONE");
        break;
      }

      case Instruction::POP:
      {
        recordStacks.pop_back();
        break;
      }
      case Instruction::MLOAD:
      case Instruction::XMLOAD:
      {
        auto stackSize = vm->stack().size();
        string res;
        uint offset = (uint)vm->stack()[stackSize - 1];
        auto iter = registerMemory.find(offset);
        if (iter != registerMemory.end())
        {
          if (iter->second.find("Id_") != string::npos)
          {
            res = iter->second;
          }
        }
        else
          res = "NONE";
        recordStacks.pop_back();
        recordStacks.push_back(res);
        break;
      }
      case Instruction::MSTORE:
      case Instruction::XMSTORE:
      case Instruction::MSTORE8:
      {
        auto stackSize = vm->stack().size();
        string res;
        auto offset = (uint)vm->stack()[stackSize - 1];
        auto value = recordStacks[stackSize - 2];
        if (value.find("Id_") != string::npos)
        {
          res = value;
        }
        else
          res = "NONE";
        registerMemory[offset] = res;

        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }

      case Instruction::SLOAD:
      case Instruction::XSLOAD:
      {
        break;
      }
      case Instruction::SSTORE:
      case Instruction::XSSTORE:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::JUMP:
      case Instruction::JUMPC:
      {
        recordStacks.pop_back();
        break;
      }
      case Instruction::JUMPI:
      case Instruction::JUMPCI:
      {

        auto stackSize = vm->stack().size();
        string res;
        auto condition = recordStacks[stackSize - 2];
        cout << "JUMPI  " << vm->stack()[stackSize - 2] << "\n";
        if (condition.find("Id_") != string::npos)
        {
          res = condition;
          cout << condition << " " << vm->stack()[stackSize - 2] << endl;
        }
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }

      case Instruction::PC:
      case Instruction::MSIZE:
      case Instruction::GAS:
      {
        recordStacks.push_back("NONE");
        break;
      }
      case Instruction::JUMPDEST:
      {
        break;
      }
      case Instruction::PUSH1:
      case Instruction::PUSH2:
      case Instruction::PUSH3:
      case Instruction::PUSH4:
      case Instruction::PUSH5:
      case Instruction::PUSH6:
      case Instruction::PUSH7:
      case Instruction::PUSH8:
      case Instruction::PUSH9:
      case Instruction::PUSH10:
      case Instruction::PUSH11:
      case Instruction::PUSH12:
      case Instruction::PUSH13:
      case Instruction::PUSH14:
      case Instruction::PUSH15:
      case Instruction::PUSH16:
      case Instruction::PUSH17:
      case Instruction::PUSH18:
      case Instruction::PUSH19:
      case Instruction::PUSH20:
      case Instruction::PUSH21:
      case Instruction::PUSH22:
      case Instruction::PUSH23:
      case Instruction::PUSH24:
      case Instruction::PUSH25:
      case Instruction::PUSH26:
      case Instruction::PUSH27:
      case Instruction::PUSH28:
      case Instruction::PUSH29:
      case Instruction::PUSH30:
      case Instruction::PUSH31:
      case Instruction::PUSH32:
      case Instruction::PUSHC:
      case Instruction::XPUSH:
      {
        recordStacks.push_back("NONE");
        break;
      }

      case Instruction::DUP1:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 1];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP2:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 2];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP3:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 3];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP4:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 4];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP5:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 5];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP6:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 6];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP7:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 7];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP8:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 8];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP9:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 9];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP10:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 10];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP11:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 11];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP12:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 12];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP13:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 13];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP14:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 14];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP15:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 15];
        recordStacks.push_back(res);
        break;
      }
      case Instruction::DUP16:
      {
        auto stackSize = vm->stack().size();
        string res = recordStacks[stackSize - 16];
        recordStacks.push_back(res);
        break;
      }

      case Instruction::SWAP1:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 2]);
        break;
      }
      case Instruction::SWAP2:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 3]);
        break;
      }
      case Instruction::SWAP3:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 4]);
        break;
      }
      case Instruction::SWAP4:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 5]);
        break;
      }
      case Instruction::SWAP5:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 6]);
        break;
      }
      case Instruction::SWAP6:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 7]);
        break;
      }
      case Instruction::SWAP7:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 8]);
        break;
      }
      case Instruction::SWAP8:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 9]);
        break;
      }
      case Instruction::SWAP9:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 10]);
        break;
      }
      case Instruction::SWAP10:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 11]);
        break;
      }
      case Instruction::SWAP11:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 12]);
        break;
      }
      case Instruction::SWAP12:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 13]);
        break;
      }
      case Instruction::SWAP13:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 14]);
        break;
      }
      case Instruction::SWAP14:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 15]);
        break;
      }
      case Instruction::SWAP15:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 16]);
        break;
      }
      case Instruction::SWAP16:
      {
        auto stackSize = vm->stack().size();
        std::swap(recordStacks[stackSize - 1], recordStacks[stackSize - 17]);
        break;
      }

      case Instruction::LOG0:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::LOG1:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::LOG2:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::LOG3:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::LOG4:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }

      case Instruction::CREATE:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::CALL:
      case Instruction::CALLCODE:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::RETURN:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::DELEGATECALL:
      case Instruction::STATICCALL:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::CREATE2:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::REVERT:
      {
        recordStacks.pop_back();
        recordStacks.pop_back();
        break;
      }
      case Instruction::SUICIDE:
      {
        recordStacks.pop_back();
        break;
      }
      default:
      {
        break;
      }
      }
    };

    program->invoke(addr, CONTRACT_FUNCTION, symbolFun, false, onOp);
  }

}
