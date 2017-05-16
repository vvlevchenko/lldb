//===-- JavaLanguage.cpp ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#ifndef liblldb_KotlinLanguageRuntime_h_
#define liblldb_KotlinLanguageRuntime_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/Target/LanguageRuntime.h"
#include "lldb/lldb-private.h"

namespace lldb_private {
class KotlinLanguageRuntime : public LanguageRuntime {

public:
    static void Initialize();
    static void Terminate();
    static lldb_private::LanguageRuntime *
    CreateInstance(Process *process, lldb::LanguageType language);
    static lldb_private::ConstString GetPluginNameStatic();

    lldb_private::ConstString GetPluginName() override;

    uint32_t GetPluginVersion() override { return 1; }

    lldb::LanguageType GetLanguageType() const override {
        return lldb::eLanguageTypeKotlin;
    }

    bool GetObjectDescription(Stream &str, ValueObject &object) override {
        return false;
    }

    bool GetObjectDescription(Stream &str, Value &value, ExecutionContextScope *exe_scope) override {
        return false;
    }

    bool GetDynamicTypeAndAddress(ValueObject &in_value, lldb::DynamicValueType use_dynamic,
                                  TypeAndOrName &class_type_or_name, Address &address,
                                  Value::ValueType &value_type) override {
        return false;
    }

    bool CouldHaveDynamicValue(ValueObject &in_value) override {
        return false;
    }

    TypeAndOrName FixUpDynamicType(const TypeAndOrName &type_and_or_name, ValueObject &static_value) override;

    lldb::BreakpointResolverSP CreateExceptionResolver(Breakpoint *bkpt, bool catch_bp, bool throw_bp) override {
        return nullptr;
    }
private:
    KotlinLanguageRuntime(Process *process);
    DISALLOW_COPY_AND_ASSIGN(KotlinLanguageRuntime);


};
}


#endif //liblldb_KotlinLanguageRuntime_h_
