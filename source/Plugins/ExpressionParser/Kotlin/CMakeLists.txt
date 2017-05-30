add_lldb_library(lldbPluginExpressionParserKotlin PLUGIN
        KotlinLexer.cpp
        KotlinParser.cpp
        KotlinUserExpression.cpp

        LINK_LIBS
        lldbCore
        lldbExpression
        lldbSymbol
        lldbTarget
        LINK_COMPONENTS
        Support
        )