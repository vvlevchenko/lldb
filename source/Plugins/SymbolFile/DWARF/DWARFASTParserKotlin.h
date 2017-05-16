//===-- DWARFASTParserKotlin.h ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef SymbolFileDWARF_DWARFASTParserKotlin_h_
#define SymbolFileDWARF_DWARFASTParserKotlin_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
// Project includes
#include <lldb/Symbol/KotlinASTContext.h>
#include "DWARFASTParser.h"
#include "DWARFDIE.h"
#include "DWARFDefines.h"
#include "lldb/Core/PluginInterface.h"
#include "lldb/Symbol/JavaASTContext.h"

class DWARFASTParserKotlin:public DWARFASTParser {

public:
    DWARFASTParserKotlin(lldb_private::KotlinASTContext& context);
};


#endif //SymbolFileDWARF_DWARFASTParserKotlin_h_
