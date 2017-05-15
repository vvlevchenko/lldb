//===-- KotlinLanguage.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_KotlinLanguage_h_
#define liblldb_KotlinLanguage_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
#include "llvm/ADT/StringRef.h"
#include "lldb/Target/Language.h"

namespace lldb_private {
class KotlinLanguage : public Language
{
public:
  lldb::LanguageType
  GetLanguageType() const override
  {
      return lldb::eLanguageTypeKotlin;
  }

    static void
    Initialize();

    static void
    Terminate();

    ConstString GetPluginName() override;

    uint32_t GetPluginVersion() override;

    static ConstString GetPluginNameStatic();

    static Language *CreateInstance(lldb::LanguageType language);
};
}


#endif //liblldb_KotlinLanguage_h_
