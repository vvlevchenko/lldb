//
// Created by Vasily Levchenko on 5/15/17.
//

#include <lldb/Core/PluginManager.h>
#include "KotlinLanguage.h"
#include "lldb/Target/Platform.h"

using namespace lldb;
using namespace lldb_private;

void
KotlinLanguage::Initialize() {
    PluginManager::RegisterPlugin(GetPluginNameStatic(), "Kotlin Language", CreateInstance);
}

void
KotlinLanguage::Terminate() {
    PluginManager::UnregisterPlugin(CreateInstance);
}

ConstString
KotlinLanguage::GetPluginNameStatic() {
    ConstString g_name("Kotlin");
    return g_name;
}

ConstString
KotlinLanguage::GetPluginName() {
    return GetPluginNameStatic();
}

uint32_t
KotlinLanguage::GetPluginVersion() {
    return 1;
}

Language *
KotlinLanguage::CreateInstance(LanguageType language) {
    if (language == eLanguageTypeKotlin)
        return new KotlinLanguage();
    else
        return nullptr;
}

std::unique_ptr<Language::TypeScavenger>
KotlinLanguage::GetTypeScavenger() {
    class KotlinTypeScavenger : public Language::ImageListTypeScavenger {
    public:
        virtual CompilerType AdjustForInclusion(CompilerType &candidate) override {
            LanguageType lang_type(candidate.GetMinimumLanguage());
            if (lang_type != eLanguageTypeKotlin)
                return CompilerType();
            if (candidate.IsTypedefType())
                return candidate.GetTypedefedType();
            return candidate;
        }
    };

    return std::unique_ptr<TypeScavenger>(new KotlinTypeScavenger());
}
