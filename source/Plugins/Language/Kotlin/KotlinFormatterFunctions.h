//===-- KotlinFormatterFunctions.h-------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_KotlinForamterFunctions_h_
#define liblldb_KotlinForamterFunctions_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/lldb-forward.h"

namespace lldb_private {
namespace formatters {

bool
KotlinStringSummaryProvider(ValueObject &valueobj, Stream &sream, const TypeSummaryOptions &options);

}
}

#endif //liblldb_KotlinForamterFunctions_h_

