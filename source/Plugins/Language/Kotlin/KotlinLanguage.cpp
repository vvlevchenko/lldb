//
// Created by Vasily Levchenko on 5/15/17.
//

#include <lldb/Core/PluginManager.h>
#include "KotlinLanguage.h"
#include "lldb/Target/Platform.h"

using namespace lldb;
using namespace lldb_private;

void
KotlinLanguage::Initialize()
{
    PluginManager::RegisterPlugin(GetPluginNameStatic(), "Kotlin Language", CreateInstance);
}

void
KotlinLanguage::Terminate()
{
    PluginManager::UnregisterPlugin(CreateInstance);
}

ConstString
KotlinLanguage::GetPluginNameStatic()
{
    ConstString g_name("Kotlin");
    return g_name;
}

ConstString
KotlinLanguage::GetPluginName()
{
    return GetPluginNameStatic();
}

uint32_t
KotlinLanguage::GetPluginVersion()
{
    return 1;
}

Language *
KotlinLanguage::CreateInstance(LanguageType language)
{
    if (language == eLanguageTypeKotlin)
        return new KotlinLanguage();
    else
        return nullptr;
}
