//
// Created by Vasily Levchenko on 5/16/17.
//

#include <lldb/Core/PluginManager.h>
#include "KotlinLanguageRuntime.h"

lldb_private::KotlinLanguageRuntime::KotlinLanguageRuntime(lldb_private::Process *process) : LanguageRuntime(process) {}

lldb_private::TypeAndOrName
lldb_private::KotlinLanguageRuntime::FixUpDynamicType(const lldb_private::TypeAndOrName &type_and_or_name,
                                                      lldb_private::ValueObject &static_value) {
    return lldb_private::TypeAndOrName();
}

lldb_private::ConstString lldb_private::KotlinLanguageRuntime::GetPluginName() {
    return GetPluginNameStatic();
}

lldb_private::ConstString lldb_private::KotlinLanguageRuntime::GetPluginNameStatic() {
    static ConstString g_name("kotlin");
    return g_name;
}

lldb_private::LanguageRuntime *
lldb_private::KotlinLanguageRuntime::CreateInstance(lldb_private::Process *process, lldb::LanguageType language) {
    if (language == lldb::eLanguageTypeKotlin)
        return new KotlinLanguageRuntime(process);
    return nullptr;
}

void lldb_private::KotlinLanguageRuntime::Initialize() {
    PluginManager::RegisterPlugin(GetPluginNameStatic(), "Kotlin Language runtime", CreateInstance);
}

void lldb_private::KotlinLanguageRuntime::Terminate() {
    PluginManager::UnregisterPlugin(CreateInstance);

}

