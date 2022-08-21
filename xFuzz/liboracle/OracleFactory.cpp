#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

void OracleFactory::initialize()
{
  function.clear();
}

void OracleFactory::finalize()
{
  functions.push_back(function);
  function.clear();
}

void OracleFactory::save(OpcodeContext ctx)
{
  function.push_back(ctx);
}

vector<bool> OracleFactory::analyze()
{
  uint8_t total = 15;
  while (vulnerabilities.size() < total)
  {
    vulnerabilities.push_back(false);
  }

  vector<bool> originVulnerability;
  while (originVulnerability.size() < total)
  {
    originVulnerability.push_back(false);
  }

  for (auto function : functions)
  {
    string funSelector = "";
    if (!function.empty() && function[0].payload.data.size() >= 4)
    {
      funSelector = toHex(function[0].payload.data).substr(0, 8);

      auto iter = funVulnerabilities.find(funSelector);

      if (iter == funVulnerabilities.end())
      {
        funVulnerabilities[funSelector] = originVulnerability;
      }
    }
    auto nowVul = originVulnerability;

    for (uint8_t i = 0; i < total; i++)
    {
      if (true || !vulnerabilities[i])
      {
        switch (i)
        {
        case GASLESS_SEND:
        {
          for (auto ctx : function)
          {
            auto level = ctx.level;
            auto inst = ctx.payload.inst;
            auto gas = ctx.payload.gas;
            auto data = ctx.payload.data;
            vulnerabilities[i] = vulnerabilities[i] || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
            nowVul[i] = nowVul[i] || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
          }
          break;
        }
        case EXCEPTION_DISORDER:
        {
          auto rootCallResponse = function[function.size() - 1];
          bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
          for (auto ctx : function)
          {
            vulnerabilities[i] = vulnerabilities[i] || (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level);
            nowVul[i] = nowVul[i] || (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level);
          }
          break;
        }
        case TIME_DEPENDENCY:
        {
          auto has_transfer = false;
          auto has_timestamp = false;
          for (auto ctx : function)
          {
            has_transfer = has_transfer || ctx.payload.wei > 0;
            has_timestamp = has_timestamp || ctx.payload.inst == Instruction::TIMESTAMP;
          }
          vulnerabilities[i] = vulnerabilities[i] || has_transfer && has_timestamp;
          nowVul[i] = nowVul[i] || has_transfer && has_timestamp;
          break;
        }
        case NUMBER_DEPENDENCY:
        {
          auto has_transfer = false;
          auto has_number = false;
          for (auto ctx : function)
          {
            has_transfer = has_transfer || ctx.payload.wei > 0;
            has_number = has_number || ctx.payload.inst == Instruction::NUMBER;
          }
          vulnerabilities[i] = vulnerabilities[i] || has_transfer && has_number;
          nowVul[i] = nowVul[i] || has_transfer && has_number;
          break;
        }
        case DELEGATE_CALL:
        {
          auto rootCall = function[0];
          auto data = rootCall.payload.data;
          auto caller = rootCall.payload.caller;
          for (auto ctx : function)
          {
            if (ctx.payload.inst == Instruction::DELEGATECALL)
            {
              vulnerabilities[i] = true;
              nowVul[i] = true;

              //while( true ) { cout<< "1 ";}
            }
          }
          break;
        }
        case REENTRANCY:
        {
          auto rootCall = function[0];
          auto caller = rootCall.payload.caller;

          auto has_loop = false;
          auto has_transfer = false;
          for (auto ctx : function)
          {
            has_loop = has_loop || (ctx.level >= 4 && toHex(ctx.payload.data) == "000000ff");
            has_transfer = has_transfer || ctx.payload.wei > 0 && (caller != Address(0xf0));
            // cout<<" ctx.level   "<< ctx.level<<"  ctx.payload.data  "<<ctx.payload.data  <<endl;
          }
          
          // if( has_loop) cout<<" has_loop "<<endl;
          // if(has_transfer) cout<<"  has_transfer"<<endl;
          vulnerabilities[i] = vulnerabilities[i] || has_loop && has_transfer;
          nowVul[i] = nowVul[i] || has_loop && has_transfer;
          break;
        }
        case FREEZING:
        {
          auto has_delegate = false;
          auto has_transfer = false;
          for (auto ctx : function)
          {
            has_delegate = has_delegate || ctx.payload.inst == Instruction::DELEGATECALL;
            has_transfer = has_transfer || (ctx.level == 1 && (ctx.payload.inst == Instruction::CALL || ctx.payload.inst == Instruction::CALLCODE || ctx.payload.inst == Instruction::SUICIDE));
          }
          vulnerabilities[i] = vulnerabilities[i] || has_delegate && !has_transfer;
          nowVul[i] = nowVul[i] || has_delegate && !has_transfer;
          break;
        }
        case UNDERFLOW:
        {
          for (auto ctx : function)
          {
            vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isUnderflow;
            nowVul[i] = nowVul[i] || ctx.payload.isUnderflow;
          }
          break;
        }
        case OVERFLOW:
        {
          for (auto ctx : function)
          {
            vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isOverflow;
            nowVul[i] = nowVul[i] || ctx.payload.isOverflow;
          }
          break;
        }
        case EXTERNALCALL:
        {
          auto isExternal = false;
          // auto has_call_out = true;
          auto has_loop = false;
          for (auto ctx : function)
          {
            isExternal = isExternal || ctx.payload.isExternalCall;
            // has_call_out = has_call_out || ctx.externalCallCount;
            has_loop = has_loop || (ctx.level >= 4 && toHex(ctx.payload.data) == "000000ff" );
            has_loop = has_loop || ctx.level >= 3 && (ctx.payload.callee<Address(0xf0) || ctx.payload.callee>Address(0xf2));
            // if(isExternal && ctx.payload.data.size()<100 )
            //   cout<<" ctx.level   "<< ctx.level<<" ctx.payload.data   "<<ctx.payload.data<<endl;


          }

          vulnerabilities[i] = vulnerabilities[i] || (isExternal  && has_loop);
          nowVul[i] = nowVul[i] || (isExternal  && has_loop);

          // if (isExternal && has_loop)
          // {
          //   for (int i = 0; i < 1; i++)
          //   {
          //     cout << "EXTERNALCALL   " << endl;
          //   }
          // }

          break;
        }

        // case EXTERNALCALL: {
        //   break;
        // }
        case TRANSFERINTARGET:
        {
          auto has_transfer = false ;
          auto is_target_function = false ;
          for (auto ctx : function)
          {

            is_target_function = is_target_function || ctx.payload.isTargetFunction;
            has_transfer = has_transfer || ctx.payload.wei > 0 && (ctx.payload.caller != Address(0xf0));
            
          }
          vulnerabilities[i] = vulnerabilities[i] || is_target_function && has_transfer;
          nowVul[i] = nowVul[i] || is_target_function && has_transfer;
          // if (vulnerabilities[i])
          // {
          //   for (int i = 0; i < 1; i++)
          //   {
          //     cout << "TRANSFERINTARGET   " <<has_transfer<< endl;
          //   }
          // }
          //while(vulnerabilities[i]) { cout<<"#";}
          break;
        }
        case TXORIGIN:
        {
          auto hasTransfer = false;
          auto hasTx = false;

          for (auto ctx : function)
          {
            hasTx = hasTx || ctx.payload.inst == Instruction::ORIGIN;
            hasTransfer = hasTransfer || hasTx && ( ctx.payload.wei > 0 ||  ctx.payload.inst ==Instruction::SSTORE );
            
          }

          vulnerabilities[i] = vulnerabilities[i] || hasTransfer && hasTx;
          nowVul[i] = nowVul[i] || hasTransfer && hasTx;
          //while(vulnerabilities[i]) { cout<<"#";}
          break;
        }
        }
      }
    }

    if (!funSelector.empty())
    {
      //cout<<funSelector<<endl;
      if (nowVul != originVulnerability && funVulnerabilities.count(funSelector))
      {
        for (int i = 0; i < total; i++)
          funVulnerabilities[funSelector][i] = funVulnerabilities[funSelector][i] || nowVul[i];
      }
    }
  }
  functions.clear();
  return vulnerabilities;
}
