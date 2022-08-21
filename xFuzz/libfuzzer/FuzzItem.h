#pragma once
#include "TargetContainer.h"
#include "Common.h"

using namespace std;
using namespace dev;
using namespace eth;

namespace fuzzer {
  struct FuzzItem {
    bytes data;
    TargetContainerResult res;
    uint64_t fuzzedCount = 0;
    uint64_t depth = 0;
    uint64_t will_cover_Jumps = 0;
    uint64_t have_cover_jumps = 0;
    FuzzItem(bytes _data) {
      data = _data;
    }
  };
  using OnMutateFunc = function<FuzzItem (bytes b)>;
}
