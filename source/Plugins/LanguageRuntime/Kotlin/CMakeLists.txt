add_lldb_library(lldbPluginLanguageRuntimeKotlin PLUGIN
        KotlinLanguageRuntime.cpp

        LINK_LIBS
        lldbCore
        lldbSymbol
        lldbTarget
        LINK_COMPONENTS
        Support
        )