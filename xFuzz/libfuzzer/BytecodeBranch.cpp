#include "BytecodeBranch.h"
#include "Logger.h"
#include "Util.h"

namespace fuzzer {
  

  BytecodeBranch::BytecodeBranch(const ContractInfo &contractInfo) {
    auto deploymentBin = contractInfo.bin.substr(0, contractInfo.bin.size() - contractInfo.binRuntime.size());
    auto progInfo = {
        make_tuple(fromHex(deploymentBin), contractInfo.srcmap, false),
        make_tuple(fromHex(contractInfo.binRuntime), contractInfo.srcmapRuntime, true),
    };
    // JUMPI inside constant function
    vector<pair<uint64_t, uint64_t>> constantJumpis;
    for (auto it : contractInfo.constantFunctionSrcmap) {
      auto elements = splitString(it, ':');
      constantJumpis.push_back(make_pair(stoi(elements[0]), stoi(elements[1])));
    }

    // added by zhang
     vector<pair<uint64_t, uint64_t>> reentrancyJumpis;
    for (auto it : contractInfo.reentrancyFunctionSrcmap) {
      auto elements = splitString(it, ':');
      reentrancyJumpis.push_back(make_pair(stoi(elements[0]), stoi(elements[1])));
    }


    for (auto progIt : progInfo) {
      auto opcodes = decodeBytecode(get<0>(progIt));
      auto isRuntime = get<2>(progIt);
      auto decompressedSourcemap = decompressSourcemap(get<1>(progIt));
      // offset - len - pc
      vector<tuple<uint64_t, uint64_t, uint64_t>> candidates;
      vector<tuple<uint64_t, uint64_t, uint64_t>> candidatesRe;
      // Find: if (x > 0 && x < 1000)
      uint64_t chooseSize = min(decompressedSourcemap.size(),opcodes.size());
      for (uint64_t i = 0; i < chooseSize; i ++) {
        if (get<1>(opcodes[i]) == Instruction::JUMPI) {
          auto offset = decompressedSourcemap[i][0];
          auto len = decompressedSourcemap[i][1];
          auto snippet = contractInfo.source.substr(offset, len);

          auto isInclude = count_if(reentrancyJumpis.begin(), reentrancyJumpis.end(), [&](const pair<uint64_t, uint64_t> &j) {
              return offset >= get<0>(j)
                     && offset + len <= get<0>(j) + get<1>(j);
          });
          //if(isInclude) cout<<"pc:  "<<hex<<get<0>(opcodes[i])<<endl;


          if (isInclude || boost::starts_with(snippet, "if")
            || boost::starts_with(snippet, "while")
            || boost::starts_with(snippet, "require")
            || boost::starts_with(snippet, "assert")
          ) {
            Logger::info("----");
            for (auto candidate : candidates) {
              if (get<0>(candidate) > offset && get<0>(candidate) + get<1>(candidate) < offset + len) {
                auto candidateSnippet = contractInfo.source.substr(get<0>(candidate), get<1>(candidate));
                auto numConstant = count_if(constantJumpis.begin(), constantJumpis.end(), [&](const pair<uint64_t, uint64_t> &j) {
                  return get<0>(candidate) >= get<0>(j)
                      && get<0>(candidate) + get<1>(candidate) <= get<0>(j) + get<1>(j);
                });
                if (!numConstant) {
                  Logger::info(candidateSnippet);
                  if (isRuntime) {
                    runtimeJumpis.insert(get<2>(candidate));
                    Logger::info("pc: " + to_string(get<2>(candidate)));
                    snippets.insert(make_pair(get<2>(candidate), candidateSnippet));
                  } else {
                    deploymentJumpis.insert(get<2>(candidate));
                    Logger::info("pc: " + to_string(get<2>(candidate)));
                    snippets.insert(make_pair(get<2>(candidate), candidateSnippet));
                  }
                }
              }
            }

            //added by zhang
            for (auto candidate : candidatesRe) {
              if (get<0>(candidate) > offset && get<0>(candidate) + get<1>(candidate) < offset + len) {
                auto numReentrancy = count_if(reentrancyJumpis.begin(), reentrancyJumpis.end(), [&](const pair<uint64_t, uint64_t> &j) {
                  return get<0>(candidate) >= get<0>(j)
                      && get<0>(candidate) + get<1>(candidate) <= get<0>(j) + get<1>(j);
                });
                if (numReentrancy) {
                  reentrancyfunctionJumpis.insert(get<2>(candidate));

                  //cout<<"BytecodeBranch pc:  "<<get<2>(candidate)<<endl;
                }
              }
            }
            auto numReentrancy = count_if(reentrancyJumpis.begin(), reentrancyJumpis.end(), [&](const pair<uint64_t, uint64_t> &j) {
              return offset >= get<0>(j)
                     && offset + len <= get<0>(j) + get<1>(j);
            });
            if (numReentrancy) {
                  reentrancyfunctionJumpis.insert(get<0>(opcodes[i]));

                  // cout<<"BytecodeBranch pc:  "<<get<0>(opcodes[i])<<endl;
                }
            candidatesRe.clear();





            auto numConstant = count_if(constantJumpis.begin(), constantJumpis.end(), [&](const pair<uint64_t, uint64_t> &j) {
              return offset >= get<0>(j)
                     && offset + len <= get<0>(j) + get<1>(j);
            });


            if (!numConstant) {
              Logger::info(contractInfo.source.substr(offset, len));
              if (isRuntime) {
                runtimeJumpis.insert(get<0>(opcodes[i]));
                Logger::info("pc: " + to_string(get<0>(opcodes[i])));
                snippets.insert(make_pair(get<0>(opcodes[i]), snippet));

                //cout<<runtimeJumpis.size()<<endl;
              } else {
                deploymentJumpis.insert(get<0>(opcodes[i]));
                Logger::info("pc: " + to_string(get<0>(opcodes[i])));
                snippets.insert(make_pair(get<0>(opcodes[i]), snippet));
              }
            }
            candidates.clear();

          } else {
            candidatesRe.push_back(make_tuple(offset, len, get<0>(opcodes[i])));
            candidates.push_back(make_tuple(offset, len, get<0>(opcodes[i])));
          }
        }
      }

      map<uint64_t, Instruction> pc2Ins;
      for( auto iter : opcodes)
      {
        pc2Ins[iter.first] = iter.second;
      }
      auto tmpreentrancyfunctionJumpis = reentrancyfunctionJumpis;
      for( auto iter : tmpreentrancyfunctionJumpis)
      {
       
        for(int i = iter-1; i>0 && i> iter-100 ; i--)
        {
          if(reentrancyfunctionJumpis.size() > 4) break;

          auto getKeyIter = pc2Ins.find(i);
          if(getKeyIter != pc2Ins.end())
          {
            if(getKeyIter->second == Instruction::JUMPI )
            {
              
              reentrancyfunctionJumpis.insert(getKeyIter->first);
            }

          }
         
        }
      }

      //for(auto  iter : reentrancyfunctionJumpis)
      //{
        //cout<<iter<<"   ";

      //}
      //cout<<endl;

      


    }
  }

  vector<pair<uint64_t, Instruction>> BytecodeBranch::decodeBytecode(bytes bytecode) {
    uint64_t pc = 0;
    vector<pair<uint64_t, Instruction>> instructions;
    while (pc < bytecode.size()) {
      auto inst = (Instruction) bytecode[pc];
      if (inst >= Instruction::PUSH1 && inst <= Instruction::PUSH32) {
        auto jumpNum = bytecode[pc] - (uint64_t) Instruction::PUSH1 + 1;
        auto payload = bytes(bytecode.begin() + pc + 1, bytecode.begin() + pc + 1 + jumpNum);
        pc += jumpNum;
      }
      instructions.push_back(make_pair(pc, inst));
      pc ++;
    }
    return instructions;
  }

  pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidJumpis() {
    for( auto iter : reentrancyfunctionJumpis)
    {
      runtimeJumpis.insert(iter);
    }
    
    //cout<<"deploymentJumpis:  "<<deploymentJumpis.size()<<"  runtimeJumpis:   "<<runtimeJumpis.size()<<"  reentrancyfunctionJumpis "<<reentrancyfunctionJumpis.size()<<endl;

    return make_pair(deploymentJumpis, /*reentrancyfunctionJumpis*/runtimeJumpis);



    if(reentrancyfunctionJumpis.size()>2)
    {
       cout<<"   LOOK!   /n";
    return make_pair(deploymentJumpis, reentrancyfunctionJumpis/*runtimeJumpis*/);
    }
    else
    {
      cout<<"   LOOK!   /n";
      return make_pair(deploymentJumpis, /*reentrancyfunctionJumpis*/runtimeJumpis);
    }
    

    
  }

  unordered_set<uint64_t> BytecodeBranch::getTargetfunctionJumpis()
  {
    return  reentrancyfunctionJumpis;
  }

  vector<vector<uint64_t>> BytecodeBranch::decompressSourcemap(string srcmap) {
    vector<vector<uint64_t>> components;
    for (auto it : splitString(srcmap, ';')) {
      auto sl = splitString(it, ':');
      auto s = sl.size() >= 1 && sl[0] != "" ? stoi(sl[0]) : components[components.size() - 1][0];
      auto l = sl.size() >= 2 && sl[1] != "" ? stoi(sl[1]) : components[components.size() - 1][1];
      components.push_back({ s, l });
    }
    return components;
  }
}
