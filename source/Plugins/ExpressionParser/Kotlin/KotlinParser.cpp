//===-- KotlinParser.cpp ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <vector>

#include "KotlinParser.h"

#include "Plugins/ExpressionParser/Kotlin/KotlinAST.h"
#include "lldb/Utility/Status.h"
#include "llvm/ADT/SmallString.h"

using namespace lldb_private;
using namespace lldb;

namespace {
llvm::StringRef DescribeToken(KotlinLexer::TokenType t) {
    switch (t) {
        case KotlinLexer::TOK_EOF:
            return "<eof>";
        case KotlinLexer::TOK_IDENTIFIER:
            return "identifier";
        case KotlinLexer::LIT_FLOAT:
            return "float";
        case KotlinLexer::LIT_IMAGINARY:
            return "imaginary";
        case KotlinLexer::LIT_INTEGER:
            return "integer";
        case KotlinLexer::LIT_RUNE:
            return "rune";
        case KotlinLexer::LIT_STRING:
            return "string";
        default:
            return KotlinLexer::LookupToken(t);
    }
}
} // namespace

class KotlinParser::Rule {
public:
    Rule(llvm::StringRef name, KotlinParser *p)
            : m_name(name), m_parser(p), m_pos(p->m_pos) {}

    std::nullptr_t error() {
        if (!m_parser->m_failed) {
            // Set m_error in case this is the top level.
            if (m_parser->m_last_tok == KotlinLexer::TOK_INVALID)
                m_parser->m_error = m_parser->m_last;
            else
                m_parser->m_error = DescribeToken(m_parser->m_last_tok);
            // And set m_last in case it isn't.
            m_parser->m_last = m_name;
            m_parser->m_last_tok = KotlinLexer::TOK_INVALID;
            m_parser->m_pos = m_pos;
        }
        return nullptr;
    }

private:
    llvm::StringRef m_name;
    KotlinParser *m_parser;
    size_t m_pos;
};

KotlinParser::KotlinParser(const char *src) : m_lexer(src), m_pos(0), m_failed(false) {}

KotlinASTStmt *KotlinParser::Statement() {
    Rule r("Statement", this);
    KotlinLexer::TokenType t = peek();
    KotlinASTStmt *ret = nullptr;
    switch (t) {
        case KotlinLexer::TOK_EOF:
        case KotlinLexer::OP_SEMICOLON:
        case KotlinLexer::OP_RPAREN:
        case KotlinLexer::OP_RBRACE:
        case KotlinLexer::TOK_INVALID:
            return EmptyStmt();
        case KotlinLexer::OP_LBRACE:
            return Block();

            /*      TODO:
          case KotlinLexer::KEYWORD_Kotlin:
            return KotlinStmt();
          case KotlinLexer::KEYWORD_RETURN:
            return ReturnStmt();
          case KotlinLexer::KEYWORD_BREAK:
          case KotlinLexer::KEYWORD_CONTINUE:
          case KotlinLexer::KEYWORD_KotlinTO:
          case KotlinLexer::KEYWORD_FALLTHROUGH:
            return BranchStmt();
          case KotlinLexer::KEYWORD_IF:
            return IfStmt();
          case KotlinLexer::KEYWORD_SWITCH:
            return SwitchStmt();
          case KotlinLexer::KEYWORD_SELECT:
            return SelectStmt();
          case KotlinLexer::KEYWORD_FOR:
            return ForStmt();
          case KotlinLexer::KEYWORD_DEFER:
            return DeferStmt();
          case KotlinLexer::KEYWORD_CONST:
          case KotlinLexer::KEYWORD_TYPE:
          case KotlinLexer::KEYWORD_VAR:
            return DeclStmt();
          case KotlinLexer::TOK_IDENTIFIER:
            if ((ret = LabeledStmt()) ||
                (ret = ShortVarDecl()))
            {
                return ret;
            }
          */
        default:
            break;
    }
    KotlinASTExpr *expr = Expression();
    if (expr == nullptr)
        return r.error();
    if (/*(ret = SendStmt(expr)) ||*/
            (ret = IncDecStmt(expr)) || (ret = Assignment(expr)) ||
            (ret = ExpressionStmt(expr))) {
        return ret;
    }
    delete expr;
    return r.error();
}

KotlinASTStmt *KotlinParser::ExpressionStmt(KotlinASTExpr *e) {
    if (Semicolon())
        return new KotlinASTExprStmt(e);
    return nullptr;
}

KotlinASTStmt *KotlinParser::IncDecStmt(KotlinASTExpr *e) {
    Rule r("IncDecStmt", this);
    if (match(KotlinLexer::OP_PLUS_PLUS))
        return Semicolon() ? new KotlinASTIncDecStmt(e, KotlinLexer::OP_PLUS_PLUS)
                           : r.error();
    if (match(KotlinLexer::OP_MINUS_MINUS))
        return Semicolon() ? new KotlinASTIncDecStmt(e, KotlinLexer::OP_MINUS_MINUS)
                           : r.error();
    return nullptr;
}

KotlinASTStmt *KotlinParser::Assignment(lldb_private::KotlinASTExpr *e) {
    Rule r("Assignment", this);
    std::vector<std::unique_ptr<KotlinASTExpr>> lhs;
    for (KotlinASTExpr *l = MoreExpressionList(); l; l = MoreExpressionList())
        lhs.push_back(std::unique_ptr<KotlinASTExpr>(l));
    switch (peek()) {
        case KotlinLexer::OP_EQ:
        case KotlinLexer::OP_PLUS_EQ:
        case KotlinLexer::OP_MINUS_EQ:
        case KotlinLexer::OP_PIPE_EQ:
        case KotlinLexer::OP_CARET_EQ:
        case KotlinLexer::OP_STAR_EQ:
        case KotlinLexer::OP_SLASH_EQ:
        case KotlinLexer::OP_PERCENT_EQ:
        case KotlinLexer::OP_LSHIFT_EQ:
        case KotlinLexer::OP_RSHIFT_EQ:
        case KotlinLexer::OP_AMP_EQ:
        case KotlinLexer::OP_AMP_CARET_EQ:
            break;
        default:
            return r.error();
    }
    // We don't want to own e until we know this is an assignment.
    std::unique_ptr<KotlinASTAssignStmt> stmt(new KotlinASTAssignStmt(false));
    stmt->AddLhs(e);
    for (auto &l : lhs)
        stmt->AddLhs(l.release());
    for (KotlinASTExpr *r = Expression(); r; r = MoreExpressionList())
        stmt->AddRhs(r);
    if (!Semicolon() || stmt->NumRhs() == 0)
        return new KotlinASTBadStmt;
    return stmt.release();
}

KotlinASTStmt *KotlinParser::EmptyStmt() {
    if (match(KotlinLexer::TOK_EOF))
        return nullptr;
    if (Semicolon())
        return new KotlinASTEmptyStmt;
    return nullptr;
}

KotlinASTStmt *KotlinParser::KotlinStmt() {
    return nullptr;
}

KotlinASTStmt *KotlinParser::ReturnStmt() {
    if (match(KotlinLexer::KEYWORD_RETURN)) {
        std::unique_ptr<KotlinASTReturnStmt> r(new KotlinASTReturnStmt());
        for (KotlinASTExpr *e = Expression(); e; e = MoreExpressionList())
            r->AddResults(e);
        return FinishStmt(r.release());
    }
    return nullptr;
}

KotlinASTStmt *KotlinParser::BranchStmt() {
    KotlinLexer::Token *tok;
    if ((tok = match(KotlinLexer::KEYWORD_BREAK)) ||
        (tok = match(KotlinLexer::KEYWORD_CONTINUE))) {
        auto *e = Identifier();
        return FinishStmt(new KotlinASTBranchStmt(e, tok->m_type));
    }

    return nullptr;
}

KotlinASTIdent *KotlinParser::Identifier() {
    if (auto *tok = match(KotlinLexer::TOK_IDENTIFIER))
        return new KotlinASTIdent(*tok);
    return nullptr;
}

KotlinASTExpr *KotlinParser::MoreExpressionList() {
    if (match(KotlinLexer::OP_COMMA)) {
        auto *e = Expression();
        if (!e)
            return syntaxerror();
        return e;
    }
    return nullptr;
}

KotlinASTIdent *KotlinParser::MoreIdentifierList() {
    if (match(KotlinLexer::OP_COMMA)) {
        auto *i = Identifier();
        if (!i)
            return syntaxerror();
        return i;
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::Expression() {
    Rule r("Expression", this);
    if (KotlinASTExpr *ret = OrExpr())
        return ret;
    return r.error();
}

KotlinASTExpr *KotlinParser::UnaryExpr() {
    switch (peek()) {
        case KotlinLexer::OP_PLUS:
        case KotlinLexer::OP_MINUS:
        case KotlinLexer::OP_BANG:
        case KotlinLexer::OP_CARET:
        case KotlinLexer::OP_STAR:
        case KotlinLexer::OP_AMP:
        case KotlinLexer::OP_LT_MINUS: {
            const KotlinLexer::Token t = next();
            if (KotlinASTExpr *e = UnaryExpr()) {
                if (t.m_type == KotlinLexer::OP_STAR)
                    return new KotlinASTStarExpr(e);
                else
                    return new KotlinASTUnaryExpr(t.m_type, e);
            }
            return syntaxerror();
        }
        default:
            return PrimaryExpr();
    }
}

KotlinASTExpr *KotlinParser::OrExpr() {
    std::unique_ptr<KotlinASTExpr> l(AndExpr());
    if (l) {
        while (match(KotlinLexer::OP_PIPE_PIPE)) {
            KotlinASTExpr *r = AndExpr();
            if (r)
                l.reset(new KotlinASTBinaryExpr(l.release(), r, KotlinLexer::OP_PIPE_PIPE));
            else
                return syntaxerror();
        }
        return l.release();
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::AndExpr() {
    std::unique_ptr<KotlinASTExpr> l(RelExpr());
    if (l) {
        while (match(KotlinLexer::OP_AMP_AMP)) {
            KotlinASTExpr *r = RelExpr();
            if (r)
                l.reset(new KotlinASTBinaryExpr(l.release(), r, KotlinLexer::OP_AMP_AMP));
            else
                return syntaxerror();
        }
        return l.release();
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::RelExpr() {
    std::unique_ptr<KotlinASTExpr> l(AddExpr());
    if (l) {
        for (KotlinLexer::Token *t;
             (t = match(KotlinLexer::OP_EQ_EQ)) || (t = match(KotlinLexer::OP_BANG_EQ)) ||
             (t = match(KotlinLexer::OP_LT)) || (t = match(KotlinLexer::OP_LT_EQ)) ||
             (t = match(KotlinLexer::OP_GT)) || (t = match(KotlinLexer::OP_GT_EQ));) {
            KotlinLexer::TokenType op = t->m_type;
            KotlinASTExpr *r = AddExpr();
            if (r)
                l.reset(new KotlinASTBinaryExpr(l.release(), r, op));
            else
                return syntaxerror();
        }
        return l.release();
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::AddExpr() {
    std::unique_ptr<KotlinASTExpr> l(MulExpr());
    if (l) {
        for (KotlinLexer::Token *t;
             (t = match(KotlinLexer::OP_PLUS)) || (t = match(KotlinLexer::OP_MINUS)) ||
             (t = match(KotlinLexer::OP_PIPE)) || (t = match(KotlinLexer::OP_CARET));) {
            KotlinLexer::TokenType op = t->m_type;
            KotlinASTExpr *r = MulExpr();
            if (r)
                l.reset(new KotlinASTBinaryExpr(l.release(), r, op));
            else
                return syntaxerror();
        }
        return l.release();
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::MulExpr() {
    std::unique_ptr<KotlinASTExpr> l(UnaryExpr());
    if (l) {
        for (KotlinLexer::Token *t;
             (t = match(KotlinLexer::OP_STAR)) || (t = match(KotlinLexer::OP_SLASH)) ||
             (t = match(KotlinLexer::OP_PERCENT)) || (t = match(KotlinLexer::OP_LSHIFT)) ||
             (t = match(KotlinLexer::OP_RSHIFT)) || (t = match(KotlinLexer::OP_AMP)) ||
             (t = match(KotlinLexer::OP_AMP_CARET));) {
            KotlinLexer::TokenType op = t->m_type;
            KotlinASTExpr *r = UnaryExpr();
            if (r)
                l.reset(new KotlinASTBinaryExpr(l.release(), r, op));
            else
                return syntaxerror();
        }
        return l.release();
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::PrimaryExpr() {
    KotlinASTExpr *l;
    KotlinASTExpr *r;
    (l = Conversion()) || (l = Operand());
    if (!l)
        return nullptr;
    while ((r = Selector(l)) || (r = IndexOrSlice(l)) || (r = TypeAssertion(l)) ||
           (r = Arguments(l))) {
        l = r;
    }
    return l;
}

KotlinASTExpr *KotlinParser::Operand() {
    KotlinLexer::Token *lit;
    if ((lit = match(KotlinLexer::LIT_INTEGER)) ||
        (lit = match(KotlinLexer::LIT_FLOAT)) ||
        (lit = match(KotlinLexer::LIT_IMAGINARY)) ||
        (lit = match(KotlinLexer::LIT_RUNE)) || (lit = match(KotlinLexer::LIT_STRING)))
        return new KotlinASTBasicLit(*lit);
    if (match(KotlinLexer::OP_LPAREN)) {
        KotlinASTExpr *e;
        if (!((e = Expression()) && match(KotlinLexer::OP_RPAREN)))
            return syntaxerror();
        return e;
    }
    // MethodExpr should be handled by Selector
    if (KotlinASTExpr *e = CompositeLit())
        return e;
    if (KotlinASTExpr *n = Name())
        return n;
    return FunctionLit();
}

KotlinASTExpr *KotlinParser::FunctionLit() {
    if (!match(KotlinLexer::KEYWORD_FUNC))
        return nullptr;
    auto *sig = Signature();
    if (!sig)
        return syntaxerror();
    auto *body = Block();
    if (!body) {
        delete sig;
        return syntaxerror();
    }
    return new KotlinASTFuncLit(sig, body);
}

KotlinASTBlockStmt *KotlinParser::Block() {
    if (!match(KotlinLexer::OP_LBRACE))
        return nullptr;
    std::unique_ptr<KotlinASTBlockStmt> block(new KotlinASTBlockStmt);
    for (auto *s = Statement(); s; s = Statement())
        block->AddList(s);
    if (!match(KotlinLexer::OP_RBRACE))
        return syntaxerror();
    return block.release();
}

KotlinASTExpr *KotlinParser::CompositeLit() {
    Rule r("CompositeLit", this);
    KotlinASTExpr *type;
    (type = ArrayOrSliceType(true)) ||
    (type = MapType()) || (type = Name());
    if (!type)
        return r.error();
    KotlinASTCompositeLit *lit = LiteralValue();
    if (!lit)
        return r.error();
    lit->SetType(type);
    return lit;
}

KotlinASTCompositeLit *KotlinParser::LiteralValue() {
    if (!match(KotlinLexer::OP_LBRACE))
        return nullptr;
    std::unique_ptr<KotlinASTCompositeLit> lit(new KotlinASTCompositeLit);
    for (KotlinASTExpr *e = Element(); e; e = Element()) {
        lit->AddElts(e);
        if (!match(KotlinLexer::OP_COMMA))
            break;
    }
    if (!mustMatch(KotlinLexer::OP_RBRACE))
        return nullptr;
    return lit.release();
}

KotlinASTExpr *KotlinParser::Element() {
    KotlinASTExpr *key;
    if (!((key = Expression()) || (key = LiteralValue())))
        return nullptr;
    if (!match(KotlinLexer::OP_COLON))
        return key;
    KotlinASTExpr *value;
    if ((value = Expression()) || (value = LiteralValue()))
        return new KotlinASTKeyValueExpr(key, value);
    delete key;
    return syntaxerror();
}

KotlinASTExpr *KotlinParser::Selector(KotlinASTExpr *e) {
    Rule r("Selector", this);
    if (match(KotlinLexer::OP_DOT)) {
        if (auto *name = Identifier())
            return new KotlinASTSelectorExpr(e, name);
    }
    return r.error();
}

KotlinASTExpr *KotlinParser::IndexOrSlice(KotlinASTExpr *e) {
    Rule r("IndexOrSlice", this);
    if (match(KotlinLexer::OP_LBRACK)) {
        std::unique_ptr<KotlinASTExpr> i1(Expression()), i2, i3;
        bool slice = false;
        if (match(KotlinLexer::OP_COLON)) {
            slice = true;
            i2.reset(Expression());
            if (i2 && match(KotlinLexer::OP_COLON)) {
                i3.reset(Expression());
                if (!i3)
                    return syntaxerror();
            }
        }
        if (!(slice || i1))
            return syntaxerror();
        if (!mustMatch(KotlinLexer::OP_RBRACK))
            return nullptr;
        if (slice) {
            bool slice3 = i3.get();
            return new KotlinASTSliceExpr(e, i1.release(), i2.release(), i3.release(),
                                      slice3);
        }
        return new KotlinASTIndexExpr(e, i1.release());
    }
    return r.error();
}

KotlinASTExpr *KotlinParser::TypeAssertion(KotlinASTExpr *e) {
    Rule r("TypeAssertion", this);
    if (match(KotlinLexer::OP_DOT) && match(KotlinLexer::OP_LPAREN)) {
        if (auto *t = Type()) {
            if (!mustMatch(KotlinLexer::OP_RPAREN))
                return nullptr;
            return new KotlinASTTypeAssertExpr(e, t);
        }
        return syntaxerror();
    }
    return r.error();
}

KotlinASTExpr *KotlinParser::Arguments(KotlinASTExpr *e) {
    if (match(KotlinLexer::OP_LPAREN)) {
        std::unique_ptr<KotlinASTCallExpr> call(new KotlinASTCallExpr(false));
        KotlinASTExpr *arg;
        // ( ExpressionList | Type [ "," ExpressionList ] )
        for ((arg = Expression()) || (arg = Type()); arg;
             arg = MoreExpressionList()) {
            call->AddArgs(arg);
        }

        // Eat trailing comma
        match(KotlinLexer::OP_COMMA);

        if (!mustMatch(KotlinLexer::OP_RPAREN))
            return nullptr;
        call->SetFun(e);
        return call.release();
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::Conversion() {
    Rule r("Conversion", this);
    if (KotlinASTExpr *t = Type2()) {
        if (match(KotlinLexer::OP_LPAREN)) {
            KotlinASTExpr *v = Expression();
            if (!v)
                return syntaxerror();
            match(KotlinLexer::OP_COMMA);
            if (!mustMatch(KotlinLexer::OP_RPAREN))
                return r.error();
            KotlinASTCallExpr *call = new KotlinASTCallExpr(false);
            call->SetFun(t);
            call->AddArgs(v);
            return call;
        }
    }
    return r.error();
}

KotlinASTExpr *KotlinParser::Type2() {
    switch (peek()) {
        case KotlinLexer::OP_LBRACK:
            return ArrayOrSliceType(false);
        case KotlinLexer::KEYWORD_FUNC:
            return FunctionType();
        case KotlinLexer::KEYWORD_INTERFACE:
            return InterfaceType();
        default:
            return nullptr;
    }
}

KotlinASTExpr *KotlinParser::ArrayOrSliceType(bool allowEllipsis) {
    Rule r("ArrayType", this);
    if (match(KotlinLexer::OP_LBRACK)) {
        std::unique_ptr<KotlinASTExpr> len;
        len.reset(Expression());


        if (!match(KotlinLexer::OP_RBRACK))
            return r.error();
        KotlinASTExpr *elem = Type();
        if (!elem)
            return syntaxerror();
        return new KotlinASTArrayType(len.release(), elem);
    }
    return r.error();
}


KotlinASTField *KotlinParser::FieldDecl() {
    std::unique_ptr<KotlinASTField> f(new KotlinASTField);
    KotlinASTExpr *t = FieldNamesAndType(f.get());
    if (!t)
        t = AnonymousFieldType();
    if (!t)
        return nullptr;

    if (auto *tok = match(KotlinLexer::LIT_STRING))
        f->SetTag(new KotlinASTBasicLit(*tok));
    if (!Semicolon())
        return syntaxerror();
    return f.release();
}

KotlinASTExpr *KotlinParser::FieldNamesAndType(KotlinASTField *field) {
    Rule r("FieldNames", this);
    for (auto *id = Identifier(); id; id = MoreIdentifierList())
        field->AddNames(id);
    if (m_failed)
        return nullptr;
    KotlinASTExpr *t = Type();
    if (t)
        return t;
    return r.error();
}

KotlinASTExpr *KotlinParser::AnonymousFieldType() {
    bool pointer = match(KotlinLexer::OP_STAR);
    KotlinASTExpr *t = Type();
    if (!t)
        return nullptr;
    if (pointer)
        return new KotlinASTStarExpr(t);
    return t;
}

KotlinASTExpr *KotlinParser::FunctionType() {
    if (!match(KotlinLexer::KEYWORD_FUNC))
        return nullptr;
    return Signature();
}

KotlinASTFuncType *KotlinParser::Signature() {
    auto *params = Params();
    if (!params)
        return syntaxerror();
    auto *result = Params();
    if (!result) {
        if (auto *t = Type()) {
            result = new KotlinASTFieldList;
            auto *f = new KotlinASTField;
            f->SetType(t);
            result->AddList(f);
        }
    }
    return new KotlinASTFuncType(params, result);
}

KotlinASTFieldList *KotlinParser::Params() {
    if (!match(KotlinLexer::OP_LPAREN))
        return nullptr;
    std::unique_ptr<KotlinASTFieldList> l(new KotlinASTFieldList);
    while (KotlinASTField *p = ParamDecl()) {
        l->AddList(p);
        if (!match(KotlinLexer::OP_COMMA))
            break;
    }
    if (!mustMatch(KotlinLexer::OP_RPAREN))
        return nullptr;
    return l.release();
}

KotlinASTField *KotlinParser::ParamDecl() {
    std::unique_ptr<KotlinASTField> field(new KotlinASTField);
    KotlinASTIdent *id = Identifier();
    if (id) {
        // Try `IdentifierList [ "..." ] Type`.
        // If that fails, backtrack and try `[ "..." ] Type`.
        Rule r("NamedParam", this);
        for (; id; id = MoreIdentifierList())
            field->AddNames(id);
        KotlinASTExpr *t = ParamType();
        if (t) {
            field->SetType(t);
            return field.release();
        }
        field.reset(new KotlinASTField);
        r.error();
    }
    KotlinASTExpr *t = ParamType();
    if (t) {
        field->SetType(t);
        return field.release();
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::ParamType() {
    KotlinASTExpr *t = Type();
    if (!t)
        return syntaxerror();
    return new KotlinASTEllipsis(t);
}

KotlinASTExpr *KotlinParser::InterfaceType() {
    if (!match(KotlinLexer::KEYWORD_INTERFACE) || !mustMatch(KotlinLexer::OP_LBRACE))
        return nullptr;
    std::unique_ptr<KotlinASTFieldList> methods(new KotlinASTFieldList);
    while (true) {
        Rule r("MethodSpec", this);
        // ( identifier Signature | TypeName ) ;
        std::unique_ptr<KotlinASTIdent> id(Identifier());
        if (!id)
            break;
        KotlinASTExpr *type = Signature();
        if (!type) {
            r.error();
            id.reset();
            type = Name();
        }
        if (!Semicolon())
            return syntaxerror();
        auto *f = new KotlinASTField;
        if (id)
            f->AddNames(id.release());
        f->SetType(type);
        methods->AddList(f);
    }
    if (!mustMatch(KotlinLexer::OP_RBRACE))
        return nullptr;
    return new KotlinASTInterfaceType(methods.release());
}

KotlinASTExpr *KotlinParser::MapType() {
    if (!(match(KotlinLexer::KEYWORD_MAP) && mustMatch(KotlinLexer::OP_LBRACK)))
        return nullptr;
    std::unique_ptr<KotlinASTExpr> key(Type());
    if (!key)
        return syntaxerror();
    if (!mustMatch(KotlinLexer::OP_RBRACK))
        return nullptr;
    auto *elem = Type();
    if (!elem)
        return syntaxerror();
    return new KotlinASTMapType(key.release(), elem);
}

KotlinASTExpr *KotlinParser::Type() {
    if (KotlinASTExpr *t = Type2())
        return t;
    if (KotlinASTExpr *t = Name())
        return t;
    if (match(KotlinLexer::OP_STAR)) {
        KotlinASTExpr *t = Type();
        if (!t)
            return syntaxerror();
        return new KotlinASTStarExpr(t);
    }
    if (match(KotlinLexer::OP_LPAREN)) {
        std::unique_ptr<KotlinASTExpr> t(Type());
        if (!t || !match(KotlinLexer::OP_RPAREN))
            return syntaxerror();
        return t.release();
    }
    return nullptr;
}

bool KotlinParser::Semicolon() {
    if (match(KotlinLexer::OP_SEMICOLON))
        return true;
    switch (peek()) {
        case KotlinLexer::OP_RPAREN:
        case KotlinLexer::OP_RBRACE:
        case KotlinLexer::TOK_EOF:
            return true;
        default:
            return false;
    }
}

KotlinASTExpr *KotlinParser::Name() {
    if (auto *id = Identifier()) {
        if (KotlinASTExpr *qual = QualifiedIdent(id))
            return qual;
        return id;
    }
    return nullptr;
}

KotlinASTExpr *KotlinParser::QualifiedIdent(lldb_private::KotlinASTIdent *p) {
    Rule r("QualifiedIdent", this);
    llvm::SmallString<32> path(p->GetName().m_value);
    KotlinLexer::Token *next;
    bool have_slashes = false;
    // LLDB extension: support full/package/path.name
    while (match(KotlinLexer::OP_SLASH) && (next = match(KotlinLexer::TOK_IDENTIFIER))) {
        have_slashes = true;
        path.append("/");
        path.append(next->m_value);
    }
    if (match(KotlinLexer::OP_DOT)) {
        auto *name = Identifier();
        if (name) {
            if (have_slashes) {
                p->SetName(KotlinLexer::Token(KotlinLexer::TOK_IDENTIFIER, CopyString(path)));
            }
            return new KotlinASTSelectorExpr(p, name);
        }
    }
    return r.error();
}

llvm::StringRef KotlinParser::CopyString(llvm::StringRef s) {
    return m_strings.insert(std::make_pair(s, 'x')).first->getKey();
}

void KotlinParser::GetError(Status &error) {
    llvm::StringRef want;
    if (m_failed)
        want =
                m_last_tok == KotlinLexer::TOK_INVALID ? DescribeToken(m_last_tok) : m_last;
    else
        want = m_error;
    size_t len = m_lexer.BytesRemaining();
    if (len > 10)
        len = 10;
    llvm::StringRef Kotlint;
    if (len == 0)
        Kotlint = "<eof>";
    else
        Kotlint = m_lexer.GetString(len);
    error.SetErrorStringWithFormat("Syntax error: expected %s before '%s'.",
                                   want.str().c_str(), Kotlint.str().c_str());
}
