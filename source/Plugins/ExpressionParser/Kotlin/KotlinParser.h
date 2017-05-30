//===-- KotlinParser.h ------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_KotlinParser_h
#define liblldb_KotlinParser_h

#include "Plugins/ExpressionParser/Kotlin/KotlinAST.h"
#include "Plugins/ExpressionParser/Kotlin/KotlinLexer.h"
#include "lldb/lldb-private.h"

namespace lldb_private {
class KotlinParser {
public:
    explicit KotlinParser(const char *src);

    KotlinASTStmt *Statement();

    KotlinASTStmt *KotlinStmt();
    KotlinASTStmt *ReturnStmt();
    KotlinASTStmt *BranchStmt();
    KotlinASTStmt *EmptyStmt();
    KotlinASTStmt *ExpressionStmt(KotlinASTExpr *e);
    KotlinASTStmt *IncDecStmt(KotlinASTExpr *e);
    KotlinASTStmt *Assignment(KotlinASTExpr *e);
    KotlinASTBlockStmt *Block();

    KotlinASTExpr *MoreExpressionList();  // ["," Expression]
    KotlinASTIdent *MoreIdentifierList(); // ["," Identifier]

    KotlinASTExpr *Expression();
    KotlinASTExpr *UnaryExpr();
    KotlinASTExpr *OrExpr();
    KotlinASTExpr *AndExpr();
    KotlinASTExpr *RelExpr();
    KotlinASTExpr *AddExpr();
    KotlinASTExpr *MulExpr();
    KotlinASTExpr *PrimaryExpr();
    KotlinASTExpr *Operand();
    KotlinASTExpr *Conversion();

    KotlinASTExpr *Selector(KotlinASTExpr *e);
    KotlinASTExpr *IndexOrSlice(KotlinASTExpr *e);
    KotlinASTExpr *TypeAssertion(KotlinASTExpr *e);
    KotlinASTExpr *Arguments(KotlinASTExpr *e);

    KotlinASTExpr *Type();
    KotlinASTExpr *Type2();
    KotlinASTExpr *ArrayOrSliceType(bool allowEllipsis);
    KotlinASTExpr *FunctionType();
    KotlinASTExpr *InterfaceType();
    KotlinASTExpr *MapType();

    KotlinASTExpr *Name();
    KotlinASTExpr *QualifiedIdent(KotlinASTIdent *p);
    KotlinASTIdent *Identifier();

    KotlinASTField *FieldDecl();
    KotlinASTExpr *AnonymousFieldType();
    KotlinASTExpr *FieldNamesAndType(KotlinASTField *f);

    KotlinASTFieldList *Params();
    KotlinASTField *ParamDecl();
    KotlinASTExpr *ParamType();
    KotlinASTFuncType *Signature();
    KotlinASTExpr *CompositeLit();
    KotlinASTExpr *FunctionLit();
    KotlinASTExpr *Element();
    KotlinASTCompositeLit *LiteralValue();

    bool Failed() const { return m_failed; }
    bool AtEOF() const {
        return m_lexer.BytesRemaining() == 0 && m_pos == m_tokens.size();
    }

    void GetError(Status &error);

private:
    class Rule;
    friend class Rule;


    std::nullptr_t syntaxerror() {
        m_failed = true;
        return nullptr;
    }
    KotlinLexer::Token &next() {
        if (m_pos >= m_tokens.size()) {
            if (m_pos != 0 && (m_tokens.back().m_type == KotlinLexer::TOK_EOF ||
                               m_tokens.back().m_type == KotlinLexer::TOK_INVALID))
                return m_tokens.back();
            m_pos = m_tokens.size();
            m_tokens.push_back(m_lexer.Lex());
        }
        return m_tokens[m_pos++];
    }
    KotlinLexer::TokenType peek() {
        KotlinLexer::Token &tok = next();
        --m_pos;
        return tok.m_type;
    }
    KotlinLexer::Token *match(KotlinLexer::TokenType t) {
        KotlinLexer::Token &tok = next();
        if (tok.m_type == t)
            return &tok;
        --m_pos;
        m_last_tok = t;
        return nullptr;
    }
    KotlinLexer::Token *mustMatch(KotlinLexer::TokenType t) {
        KotlinLexer::Token *tok = match(t);
        if (tok)
            return tok;
        return syntaxerror();
    }
    bool Semicolon();

    KotlinASTStmt *FinishStmt(KotlinASTStmt *s) {
        if (!Semicolon())
            m_failed = true;
        return s;
    }

    llvm::StringRef CopyString(llvm::StringRef s);

    KotlinLexer m_lexer;
    std::vector<KotlinLexer::Token> m_tokens;
    size_t m_pos;
    llvm::StringRef m_error;
    llvm::StringRef m_last;
    KotlinLexer::TokenType m_last_tok;
    llvm::StringMap<uint8_t> m_strings;
    bool m_failed;
};
}

#endif
