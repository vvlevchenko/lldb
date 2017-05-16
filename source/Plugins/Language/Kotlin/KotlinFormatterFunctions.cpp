//===-- KotlinFormatterFunctions.h-------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "KotlinFormatterFunctions.h"
#include "lldb/DataFormatters/FormattersHelpers.h"
#include "lldb/DataFormatters/StringPrinter.h"
#include "lldb/Symbol/JavaASTContext.h"

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::formatters;

namespace
{
bool
KotlinStringSummaryProvider(ValueObject &valueobj, Stream &sream, const TypeSummaryOptions &options) {
    return false;
}
}