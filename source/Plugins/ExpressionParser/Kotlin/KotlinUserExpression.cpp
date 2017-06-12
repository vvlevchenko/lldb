//===-- KotlinUserExpression.cpp ---------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

// C Includes
#include <stdio.h>
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

// C++ Includes
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>
#include <regex>

// Other libraries and framework includes
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include <llvm/IR/IRBuilder.h>

// Project includes
#include "KotlinUserExpression.h"

#include "lldb/Core/Module.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Core/ValueObjectConstResult.h"
#include "lldb/Core/ValueObjectRegister.h"
#include "lldb/Expression/DiagnosticManager.h"
#include "lldb/Expression/ExpressionVariable.h"
#include "lldb/Symbol/Function.h"
#include "lldb/Symbol/KotlinASTContext.h"
#include "lldb/Symbol/SymbolFile.h"
#include "lldb/Symbol/TypeList.h"
#include "lldb/Symbol/VariableList.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Target/StackFrame.h"
#include "lldb/Target/Target.h"
#include "lldb/Target/ThreadPlan.h"
#include "lldb/Target/ThreadPlanCallUserExpression.h"
#include "lldb/Utility/ConstString.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/DataEncoder.h"
#include "lldb/Utility/DataExtractor.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/StreamString.h"
#include "lldb/lldb-private.h"

#include "Plugins/ExpressionParser/Kotlin/KotlinAST.h"
#include "Plugins/ExpressionParser/Kotlin/KotlinParser.h"

using namespace lldb_private;
using namespace lldb;

static std::string unescape(const std::string &string_name) {
    std::string unescaped = regex_replace(string_name, std::regex("\\\\"), "");
    return unescaped;
}

class KotlinUserExpression::KotlinInterpreter {
public:
    KotlinInterpreter(ExecutionContext &exe_ctx, const char *expr, Log *log)
            : m_exe_ctx(exe_ctx), m_frame(exe_ctx.GetFrameSP()), m_parser(expr), m_log(log) {
        if (m_frame) {
            const SymbolContext &ctx =
                    m_frame->GetSymbolContext(eSymbolContextFunction);
            ConstString fname = ctx.GetFunctionName();
            if (fname.GetLength() > 0) {
                size_t dot = fname.GetStringRef().find('.');
                if (dot != llvm::StringRef::npos)
                    m_package = llvm::StringRef(fname.AsCString(), dot);
            }
        }
        m_module.reset(new llvm::Module(llvm::StringRef(), m_ctx));
        m_builder.reset(new llvm::IRBuilder<>(m_ctx));
    }

    ~KotlinInterpreter() {
        m_module.reset();
        m_builder.reset();
    }

    void set_use_dynamic(DynamicValueType use_dynamic) {
        m_use_dynamic = use_dynamic;
    }

    bool Parse();
    llvm::Value* Evaluate(ExecutionContext &exe_ctx);
    llvm::Value* EvaluateStatement(const KotlinASTStmt *s);
    llvm::Value* EvaluateExpr(const KotlinASTExpr *e);

    llvm::Value* VisitBadExpr(const KotlinASTBadExpr *e) {
        m_parser.GetError(m_error);
        return nullptr;
    }

    llvm::Value* VisitParenExpr(const KotlinASTParenExpr *e);
    llvm::Value* VisitIdent(const KotlinASTIdent *e);
    llvm::Value* VisitStarExpr(const KotlinASTStarExpr *e);
    llvm::Value* VisitSelectorExpr(const KotlinASTSelectorExpr *e);
    llvm::Value* VisitBasicLit(const KotlinASTBasicLit *e);
    llvm::Value* VisitIndexExpr(const KotlinASTIndexExpr *e);
    llvm::Value* VisitUnaryExpr(const KotlinASTUnaryExpr *e);
    llvm::Value* VisitCallExpr(const KotlinASTCallExpr *e);

    llvm::Value* VisitTypeAssertExpr(const KotlinASTTypeAssertExpr *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitBinaryExpr(const KotlinASTBinaryExpr *e) {
        Log *log(lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_EXPRESSIONS));
        log->Printf("(%d %s %s)", e->GetOp(), e->GetX()->GetKindName(), e->GetY()->GetKindName());

        auto vx = e->GetX()->Visit<llvm::Value *>(this);
        auto vy = e->GetY()->Visit<llvm::Value *>(this);

        return NotImplemented(e);
    }

    llvm::Value* VisitArrayType(const KotlinASTArrayType *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitChanType(const KotlinASTChanType *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitCompositeLit(const KotlinASTCompositeLit *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitEllipsis(const KotlinASTEllipsis *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitFuncType(const KotlinASTFuncType *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitFuncLit(const KotlinASTFuncLit *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitInterfaceType(const KotlinASTInterfaceType *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitKeyValueExpr(const KotlinASTKeyValueExpr *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitMapType(const KotlinASTMapType *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitSliceExpr(const KotlinASTSliceExpr *e) {
        return NotImplemented(e);
    }

    llvm::Value* VisitStructType(const KotlinASTStructType *e) {
        return NotImplemented(e);
    }

    CompilerType EvaluateType(const KotlinASTExpr *e);

    Status &error() { return m_error; }

private:
    llvm::Value *NotImplemented(const KotlinASTExpr *e) {
        m_error.SetErrorStringWithFormat("%s node not implemented",
                                         e->GetKindName());
        return nullptr;
    }

    ExecutionContext m_exe_ctx;
    lldb::StackFrameSP m_frame;
    KotlinParser m_parser;
    DynamicValueType m_use_dynamic;
    Status m_error;
    llvm::StringRef m_package;
    std::vector<std::unique_ptr<KotlinASTStmt>> m_statements;
    std::unique_ptr<llvm::Module> m_module;
    std::unique_ptr<llvm::IRBuilder<>> m_builder;
    llvm::LLVMContext m_ctx;
    Log* m_log;
};

static VariableSP FindGlobalVariable(TargetSP target, llvm::Twine name) {
    ConstString fullname(name.str());
    VariableList variable_list;
    const bool append = true;
    if (!target) {
        return nullptr;
    }
    const uint32_t match_count = target->GetImages().FindGlobalVariables(
            fullname, append, 1, variable_list);
    if (match_count == 1) {
        return variable_list.GetVariableAtIndex(0);
    }
    return nullptr;
}

static CompilerType LookupType(TargetSP target, ConstString name) {
    if (!target)
        return CompilerType();
    SymbolContext sc;
    TypeList type_list;
    llvm::DenseSet<SymbolFile *> searched_symbol_files;
    uint32_t num_matches = target->GetImages().FindTypes(
            sc, name, false, 2, searched_symbol_files, type_list);
    if (num_matches > 0) {
        return type_list.GetTypeAtIndex(0)->GetFullCompilerType();
    }
    return CompilerType();
}

KotlinUserExpression::KotlinUserExpression(ExecutionContextScope &exe_scope,
                                   llvm::StringRef expr, llvm::StringRef prefix,
                                   lldb::LanguageType language,
                                   ResultType desired_type,
                                   const EvaluateExpressionOptions &options)
        : LLVMUserExpression(exe_scope, expr, prefix, language, desired_type, options) {
}

bool KotlinUserExpression::Parse(DiagnosticManager &diagnostic_manager,
                             ExecutionContext &exe_ctx,
                             lldb_private::ExecutionPolicy execution_policy,
                             bool keep_result_in_memory,
                             bool generate_debug_info) {
    m_log = lldb_private::GetLogIfAllCategoriesSet(LIBLLDB_LOG_EXPRESSIONS);
    InstallContext(exe_ctx);
    Status err;
    ScanContext(exe_ctx, err);

    if (!err.Success()) {
        diagnostic_manager.PutString(eDiagnosticSeverityWarning, err.AsCString());
    }
    m_materializer_ap.reset(new Materializer());
    m_interpreter.reset(new KotlinInterpreter(exe_ctx, GetUserText(), m_log));
    if (m_interpreter->Parse())
        return true;
    const char *error_cstr = m_interpreter->error().AsCString();
    if (error_cstr && error_cstr[0])
        diagnostic_manager.PutString(eDiagnosticSeverityError, error_cstr);
    else
        diagnostic_manager.Printf(eDiagnosticSeverityError,
                                  "expression can't be interpreted or run");
    return false;
}

lldb::ExpressionResults
KotlinUserExpression::DoExecute(DiagnosticManager &diagnostic_manager,
                            ExecutionContext &exe_ctx,
                            const EvaluateExpressionOptions &options,
                            lldb::UserExpressionSP &shared_ptr_to_me,
                            lldb::ExpressionVariableSP &result) {
    lldb_private::ExecutionPolicy execution_policy = options.GetExecutionPolicy();
    lldb::ExpressionResults execution_results = lldb::eExpressionSetupError;

    Process *process = exe_ctx.GetProcessPtr();
    Target *target = exe_ctx.GetTargetPtr();

    if (target == nullptr || process == nullptr ||
        process->GetState() != lldb::eStateStopped) {
        if (execution_policy == eExecutionPolicyAlways) {
            if (m_log)
                m_log->Printf("== [KotlinUserExpression::Evaluate] Expression may not run, "
                                    "but is not constant ==");

            diagnostic_manager.PutString(eDiagnosticSeverityError,
                                         "expression needed to run but couldn't");

            return execution_results;
        }
    }

    m_interpreter->set_use_dynamic(options.GetUseDynamic());
    auto result_val_sp = m_interpreter->Evaluate(exe_ctx);
    Status err = m_interpreter->error();
    m_interpreter.reset();

    if (!result_val_sp) {
        const char *error_cstr = err.AsCString();
        if (error_cstr && error_cstr[0])
            diagnostic_manager.PutString(eDiagnosticSeverityError, error_cstr);
        else
            diagnostic_manager.PutString(eDiagnosticSeverityError,
                                         "expression can't be interpreted or run");
        return lldb::eExpressionDiscarded;
    }
#if 0
    result.reset(new ExpressionVariable(ExpressionVariable::eKindKotlin));
    //result->m_live_sp = result->m_frozen_sp = result_val_sp;
    result->m_flags |= ExpressionVariable::EVIsProgramReference;
    PersistentExpressionState *pv =
            target->GetPersistentExpressionStateForLanguage(eLanguageTypeKotlin);
    if (pv != nullptr) {
        result->SetName(pv->GetNextPersistentVariableName());
        pv->AddVariable(result);
    }
#else
    result.reset();
#endif
    return lldb::eExpressionCompleted;
}

void KotlinUserExpression::ScanContext(ExecutionContext &exe_ctx,
                 lldb_private::Status &err) {
    if (m_log)
        m_log->Printf("ClangUserExpression::ScanContext()");

}

bool KotlinUserExpression::AddArguments(ExecutionContext &exe_ctx, std::vector<lldb::addr_t> &args,
                  lldb::addr_t struct_address,
                  DiagnosticManager &diagnostic_manager) {
    return false;
}

bool KotlinUserExpression::KotlinInterpreter::Parse() {
    for (std::unique_ptr<KotlinASTStmt> stmt(m_parser.Statement()); stmt;
         stmt.reset(m_parser.Statement())) {
        if (m_parser.Failed())
            break;
        m_statements.emplace_back(std::move(stmt));
    }
    if (m_parser.Failed() || !m_parser.AtEOF())
        m_parser.GetError(m_error);
    return m_error.Success();
}

llvm::Value*
KotlinUserExpression::KotlinInterpreter::Evaluate(ExecutionContext &exe_ctx) {
    llvm::Type *return_type = llvm::Type::getPrimitiveType(m_ctx, llvm::Type::TypeID::VoidTyID);
    llvm::FunctionType* generated_function_type = llvm::FunctionType::get(return_type, false);
    llvm::Function *generated_function = llvm::Function::Create(
            generated_function_type,
            llvm::GlobalValue::LinkageTypes::AvailableExternallyLinkage,
            "",
            m_module.get());
    llvm::BasicBlock *bb = llvm::BasicBlock::Create(m_ctx, "", generated_function);
    m_builder->SetInsertPoint(bb);

    m_exe_ctx = exe_ctx;
    llvm::Value *result;
    for (const std::unique_ptr<KotlinASTStmt> &stmt : m_statements) {
        result = EvaluateStatement(stmt.get());
        if (m_error.Fail())
            return nullptr;
        m_builder->CreateRet(result);
    }
    if (m_log) {
        std::string msg;
        llvm::raw_string_ostream sstream(msg);
        m_module->print(sstream, nullptr, false, true);
        m_log->Printf("bitcode:\n %s", sstream.str().c_str());
    }

    return result;
}

llvm::Value* KotlinUserExpression::KotlinInterpreter::EvaluateStatement(
        const lldb_private::KotlinASTStmt *stmt) {
    llvm::Value *result;
    switch (stmt->GetKind()) {
        case KotlinASTNode::eBlockStmt: {
            const KotlinASTBlockStmt *block = llvm::cast<KotlinASTBlockStmt>(stmt);
            for (size_t i = 0; i < block->NumList(); ++i)
                result = EvaluateStatement(block->GetList(i));
            break;
        }
        case KotlinASTNode::eBadStmt:
            m_parser.GetError(m_error);
            break;
        case KotlinASTNode::eExprStmt: {
            const KotlinASTExprStmt *expr = llvm::cast<KotlinASTExprStmt>(stmt);
            return EvaluateExpr(expr->GetX());
        }
        default:
            m_error.SetErrorStringWithFormat("%s node not supported",
                                             stmt->GetKindName());
    }
    return result;
}

llvm::Value* KotlinUserExpression::KotlinInterpreter::EvaluateExpr(
        const lldb_private::KotlinASTExpr *e) {
    if (e)
        return e->Visit<llvm::Value*>(this);
    return NotImplemented(e);
}

llvm::Value* KotlinUserExpression::KotlinInterpreter::VisitParenExpr(
        const lldb_private::KotlinASTParenExpr *e) {
    return EvaluateExpr(e->GetX());
}

llvm::Value* KotlinUserExpression::KotlinInterpreter::VisitIdent(const KotlinASTIdent *e) {
#if 0
    ValueObjectSP val;
    const std::string &string_name = e->GetName().m_value.str();
    if (m_frame) {
        VariableSP var_sp;
        std::string varname = string_name;
        if (varname.size() > 1 && varname[0] == '$') {
            RegisterContextSP reg_ctx_sp = m_frame->GetRegisterContext();
            const RegisterInfo *reg =
                    reg_ctx_sp->GetRegisterInfoByName(varname.c_str() + 1);
            if (reg) {
                std::string type;
                switch (reg->encoding) {
                    case lldb::eEncodingSint:
                        type.append("int");
                        break;
                    case lldb::eEncodingUint:
                        type.append("uint");
                        break;
                    case lldb::eEncodingIEEE754:
                        type.append("float");
                        break;
                    default:
                        m_error.SetErrorString("Invalid register encoding");
                        return nullptr;
                }
                switch (reg->byte_size) {
                    case 8:
                        type.append("64");
                        break;
                    case 4:
                        type.append("32");
                        break;
                    case 2:
                        type.append("16");
                        break;
                    case 1:
                        type.append("8");
                        break;
                    default:
                        m_error.SetErrorString("Invalid register size");
                        return nullptr;
                }
                ValueObjectSP regVal = ValueObjectRegister::Create(
                        m_frame.get(), reg_ctx_sp, reg->kinds[eRegisterKindLLDB]);
                CompilerType KotlinType =
                        LookupType(m_frame->CalculateTarget(), ConstString(type));
                if (regVal) {
                    regVal = regVal->Cast(KotlinType);
                    return regVal;
                }
            }
            m_error.SetErrorString("Invalid register name");
            return nullptr;
        }
        VariableListSP var_list_sp(m_frame->GetInScopeVariableList(false));
        if (var_list_sp) {
            var_sp = var_list_sp->FindVariable(ConstString(varname));
            if (var_sp)
                val = m_frame->GetValueObjectForFrameVariable(var_sp, m_use_dynamic);
            //else {
            //    // When a variable is on the heap instead of the stack, Kotlin records a
            //    // variable
            //    // '&x' instead of 'x'.
            //    var_sp = var_list_sp->FindVariable(ConstString("&" + varname));
            //    if (var_sp) {
            //        val = m_frame->GetValueObjectForFrameVariable(var_sp, m_use_dynamic);
            //        if (val)
            //            val = val->Dereference(m_error);
            //        if (m_error.Fail())
            //            return nullptr;
            //    }
            //}
        }
        if (!val) {
            m_error.Clear();
            TargetSP target = m_frame->CalculateTarget();
            if (!target) {
                m_error.SetErrorString("No target");
                return nullptr;
            }
            var_sp =
                    FindGlobalVariable(target, m_package + "." + e->GetName().m_value);
            if (var_sp)
                return m_frame->TrackGlobalVariable(var_sp, m_use_dynamic);
            else {
                SymbolContextList sc_list;
                std::string unescaped = unescape(string_name);
                target->GetImages().FindFunctions(ConstString(unescaped.c_str()), eFunctionNameTypeAuto, false, false, false, sc_list);
                if (sc_list.GetSize() != 0) {
                    auto address = sc_list[0].function->GetAddressRange().GetBaseAddress().GetLoadAddress(target.get());
                    return ValueObject::CreateValueObjectFromAddress(llvm::StringRef(),
                                                                     address, m_exe_ctx,
                                                                     sc_list[0].function->GetCompilerType());
                }
            }
        }
    }
    if (!val)
        m_error.SetErrorStringWithFormat("Unknown variable %s",
                                         string_name.c_str());
    return val;
#else
    TargetSP target = m_frame->CalculateTarget();
    if (!target) {
        m_error.SetErrorString("No target");
        return nullptr;
    }
    const std::string &string_name = e->GetName().m_value.str();
    SymbolContextList sc_list;
    std::string unescaped = unescape(string_name);
    size_t size = target->GetImages().FindFunctions(ConstString(unescaped.c_str()), eFunctionNameTypeAuto, false, false, false, sc_list);
    if (size > 0) {
        auto function_type = sc_list[0].function->GetType();
        if (m_log) {
            lldb_private::StreamString sstream;
            sstream.Printf("function type:");
            function_type->Dump(&sstream, true);
            sstream.EOL();
            sstream.Printf("compiler type:");
            const CompilerType &compiler_type = function_type->GetLayoutCompilerType();
            compiler_type.DumpTypeDescription(&sstream);
            bool variadic;
            if (compiler_type.IsFunctionType(&variadic)) {
                CompilerType return_type = compiler_type.GetFunctionReturnType();
                sstream.Printf("return type:\n");
                return_type.DumpTypeDescription(&sstream);
                int argument_count = compiler_type.GetFunctionArgumentCount();
                for (int i = 0; i != argument_count; ++i) {
                    CompilerType argument_type = compiler_type.GetFunctionArgumentAtIndex(i);
                    sstream.Printf("argument[%d] type: %s:\n");
                    argument_type.DumpTypeDescription(&sstream);
                }
            }
            m_log->Printf("%s", sstream.GetString().str().c_str());
        }
    }

    return NotImplemented(e);
#endif
}

llvm::Value*
KotlinUserExpression::KotlinInterpreter::VisitStarExpr(const KotlinASTStarExpr *e) {
#if 0
    ValueObjectSP target = EvaluateExpr(e->GetX());
    if (!target)
        return nullptr;
    return target->Dereference(m_error);
#else
    return NotImplemented(e);
#endif
}

llvm::Value* KotlinUserExpression::KotlinInterpreter::VisitSelectorExpr(
        const lldb_private::KotlinASTSelectorExpr *e) {
#if 0
    ValueObjectSP target = EvaluateExpr(e->GetX());
    if (target) {
        if (target->GetCompilerType().IsPointerType()) {
            target = target->Dereference(m_error);
            if (m_error.Fail())
                return nullptr;
        }
        ConstString field(e->GetSel()->GetName().m_value);
        ValueObjectSP result = target->GetChildMemberWithName(field, true);
        if (!result)
            m_error.SetErrorStringWithFormat("Unknown child %s", field.AsCString());
        return result;
    }
    if (const KotlinASTIdent *package = llvm::dyn_cast<KotlinASTIdent>(e->GetX())) {
        if (VariableSP global = FindGlobalVariable(
                m_exe_ctx.GetTargetSP(), package->GetName().m_value + "." +
                                         e->GetSel()->GetName().m_value)) {
            if (m_frame) {
                m_error.Clear();
                return m_frame->GetValueObjectForFrameVariable(global, m_use_dynamic);
            }
        }
    }
    if (const KotlinASTBasicLit *packageLit =
            llvm::dyn_cast<KotlinASTBasicLit>(e->GetX())) {
        if (packageLit->GetValue().m_type == KotlinLexer::LIT_STRING) {
            std::string value = packageLit->GetValue().m_value.str();
            value = value.substr(1, value.size() - 2);
            if (VariableSP global = FindGlobalVariable(
                    m_exe_ctx.GetTargetSP(),
                    value + "." + e->GetSel()->GetName().m_value)) {
                if (m_frame) {
                    m_error.Clear();
                    return m_frame->TrackGlobalVariable(global, m_use_dynamic);
                }
            }
        }
    }
    // EvaluateExpr should have already set m_error.
    return target;
#else
    return NotImplemented(e);
#endif
}

llvm::Value* KotlinUserExpression::KotlinInterpreter::VisitBasicLit(
        const lldb_private::KotlinASTBasicLit *e) {
    std::string value = e->GetValue().m_value.str();
    CompilerType type;
    TargetSP target = m_exe_ctx.GetTargetSP();
    if (!target) {
        m_error.SetErrorString("No target");
        return nullptr;
    }
    switch (e->GetValue().m_type) {
        case KotlinLexer::LIT_INTEGER: {
            int64_t intvalue = strtol(value.c_str(), nullptr, 0);
#if 0
            type = LookupType(target, ConstString("kotlin.Long"));
            errno = 0;
            if (errno != 0) {
                m_error.SetErrorToErrno();
                return nullptr;
            }
            DataBufferSP buf(new DataBufferHeap(sizeof(intvalue), 0));
            ByteOrder order = target->GetArchitecture().GetByteOrder();
            uint8_t addr_size = target->GetArchitecture().GetAddressByteSize();
            DataEncoder enc(buf, order, addr_size);
            enc.PutU64(0, static_cast<uint64_t>(intvalue));
            DataExtractor data(buf, order, addr_size);
#endif
            return llvm::ConstantInt::get(llvm::IntegerType::get(m_ctx, 64), intvalue, true);
        }
        case KotlinLexer::LIT_STRING:
        default:
            return NotImplemented(e);
    }

}

llvm::Value* KotlinUserExpression::KotlinInterpreter::VisitIndexExpr(
        const lldb_private::KotlinASTIndexExpr *e) {
#if 0
    ValueObjectSP target = EvaluateExpr(e->GetX());
    if (!target)
        return nullptr;
    ValueObjectSP index = EvaluateExpr(e->GetIndex());
    if (!index)
        return nullptr;
    bool is_signed;
    if (!index->GetCompilerType().IsIntegerType(is_signed)) {
        m_error.SetErrorString("Unsupported index");
        return nullptr;
    }
    size_t idx;
    if (is_signed)
        idx = index->GetValueAsSigned(0);
    else
        idx = index->GetValueAsUnsigned(0);
    return target->GetChildAtIndex(idx, true);
#else
    NotImplemented(e);
#endif
}

llvm::Value*
KotlinUserExpression::KotlinInterpreter::VisitUnaryExpr(const KotlinASTUnaryExpr *e) {
#if 0
    ValueObjectSP x = EvaluateExpr(e->GetX());
    if (!x)
        return nullptr;
    switch (e->GetOp()) {
        case KotlinLexer::OP_AMP: {
            CompilerType type = x->GetCompilerType().GetPointerType();
            uint64_t address = x->GetAddressOf();
            return ValueObject::CreateValueObjectFromAddress(llvm::StringRef(), address,
                                                             m_exe_ctx, type);
        }
        case KotlinLexer::OP_PLUS:
            return x;
        default:
            m_error.SetErrorStringWithFormat(
                    "Operator %s not supported",
                    KotlinLexer::LookupToken(e->GetOp()).str().c_str());
            return nullptr;
    }
#else
    return NotImplemented(e);
#endif
}

CompilerType KotlinUserExpression::KotlinInterpreter::EvaluateType(const KotlinASTExpr *e) {
    TargetSP target = m_exe_ctx.GetTargetSP();
    if (auto *id = llvm::dyn_cast<KotlinASTIdent>(e)) {
        //CompilerType result =
        //        LookupType(target, ConstString(unescape(id->GetName().m_value.str())));
        //if (result.IsValid())
        //    return result;
        //std::string fullname = (m_package + "." + id->GetName().m_value).str();
        //result = LookupType(target, ConstString(fullname));
        //if (!result)
        //    m_error.SetErrorStringWithFormat("Unknown type %s", fullname.c_str());
        //return result;
        return LookupType(target, ConstString("kotlin.Int"));
    }
    if (auto *sel = llvm::dyn_cast<KotlinASTSelectorExpr>(e)) {
        std::string package;
        if (auto *pkg_node = llvm::dyn_cast<KotlinASTIdent>(sel->GetX())) {
            package = pkg_node->GetName().m_value.str();
        } else if (auto *str_node = llvm::dyn_cast<KotlinASTBasicLit>(sel->GetX())) {
            if (str_node->GetValue().m_type == KotlinLexer::LIT_STRING) {
                package = str_node->GetValue().m_value.substr(1).str();
                package.resize(package.length() - 1);
            }
        }
        if (package.empty()) {
            m_error.SetErrorStringWithFormat("Invalid %s in type expression",
                                             sel->GetX()->GetKindName());
            return CompilerType();
        }
        std::string fullname =
                (package + "." + sel->GetSel()->GetName().m_value).str();
        CompilerType result = LookupType(target, ConstString(fullname));
        if (!result)
            m_error.SetErrorStringWithFormat("Unknown type %s", fullname.c_str());
        return result;
    }
    if (auto *star = llvm::dyn_cast<KotlinASTStarExpr>(e)) {
        CompilerType elem = EvaluateType(star->GetX());
        return elem.GetPointerType();
    }
    if (auto *paren = llvm::dyn_cast<KotlinASTParenExpr>(e))
        return EvaluateType(paren->GetX());
    if (auto *array = llvm::dyn_cast<KotlinASTArrayType>(e)) {
        CompilerType elem = EvaluateType(array->GetElt());
    }

    m_error.SetErrorStringWithFormat("Invalid %s in type expression",
                                     e->GetKindName());
    return CompilerType();
}

llvm::Value* KotlinUserExpression::KotlinInterpreter::VisitCallExpr(
        const lldb_private::KotlinASTCallExpr *e) {
#if 0
    ValueObjectSP x = EvaluateExpr(e->GetFun());
    /* if (x || e->NumArgs() != 1) {
        m_error.SetErrorStringWithFormat("Code execution not supported");
        return nullptr;
    }*/
    m_error.Clear();
    CompilerType type = EvaluateType(e->GetFun());
    if (!type) {
        return nullptr;
    }
    ValueObjectSP value = EvaluateExpr(e);
    if (!value)
        return nullptr;
    // TODO: Handle special conversions
    return value->Cast(type);
#endif
    EvaluateExpr(e->GetFun());
    size_t argument_number = e->NumArgs();
    std::vector<llvm::Value*>args(argument_number);
    for (int i = 0; i != argument_number; ++i) {
        args[i] = EvaluateExpr(e->GetArgs(i));
    }
    //return m_builder->CreateCall(e->GetFunction(), args);
    return NotImplemented(e);
}

KotlinPersistentExpressionState::KotlinPersistentExpressionState()
        : PersistentExpressionState(eKindKotlin) {}

ConstString KotlinPersistentExpressionState::GetNextPersistentVariableName() {
    char name_cstr[256];
    // We can't use the same variable format as clang.
    ::snprintf(name_cstr, sizeof(name_cstr), "$Kotlin%u",
               m_next_persistent_variable_id++);
    ConstString name(name_cstr);
    return name;
}

void KotlinPersistentExpressionState::RemovePersistentVariable(
        lldb::ExpressionVariableSP variable) {
    RemoveVariable(variable);

    const char *name = variable->GetName().AsCString();

    if (*(name++) != '$')
        return;
    if (*(name++) != 'g')
        return;
    if (*(name++) != 'o')
        return;

    if (strtoul(name, nullptr, 0) == m_next_persistent_variable_id - 1)
        m_next_persistent_variable_id--;
}

