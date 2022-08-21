#pragma once
#include<iostream>
#include <fstream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;
namespace fuzzer {
  class Logger {
    public:
      static bool enabled;
      static ofstream debugFile;
      static ofstream infoFile;
      static ofstream resFile;
      static void setEnabled(bool _enabled);
      static void info(string str);
      static void debug(string str);
      static string testFormat(bytes data);
      static void res(string str) ;
  };
}
