// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <ctime>
#if __GNUC__ < 8
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#include <filesystem>
namespace fs = std::filesystem;
#endif
#include <fstream>
#include <iostream>

namespace COMPILER {

void dumpAsm(const char *Buf, size_t Size, uint8_t *CodePtr) {
  const std::string &BufAddr = std::to_string(reinterpret_cast<uintptr_t>(Buf));
  fs::path FilePath = fs::temp_directory_path() / ("asmdump-" + BufAddr);
  std::ofstream File(FilePath, std::ios::out | std::ios::binary);
  if (!File) {
    llvm::errs() << "Cannot open tmp file '" << FilePath << "' for asm dump!\n";
    return;
  }
  File.write(Buf, Size);
  File.close();
  if (!File.good()) {
    llvm::errs() << "Error occurred at writing '" << FilePath << "'!\n";
    return;
  }
  llvm::dbgs() << "\n########## Assembly Dump ##########\n\n";
  char Command[512];
  int ret = 0;
  if (CodePtr) {
    ret = std::snprintf(Command, sizeof(Command),
                        "/usr/bin/objdump -d --adjust-vma=%#" PRIxPTR " %s",
                        reinterpret_cast<uintptr_t>(CodePtr), FilePath.c_str());
  } else {
    ret = std::snprintf(Command, sizeof(Command), "/usr/bin/objdump -d %s",
                        FilePath.c_str());
  }
  if (ret < 0 || (size_t)ret >= sizeof(Command)) {
    llvm::errs() << "Failed to construct objdump command for '" << FilePath
                 << "'!\n";
    return;
  }
  if (system(Command) < 0) {
    llvm::errs() << "Failed to execute objdump for '" << FilePath << "'!\n";
    return;
  }
#ifndef ZEN_ENABLE_LINUX_PERF
  fs::remove(FilePath);
#endif
}

} // namespace COMPILER
