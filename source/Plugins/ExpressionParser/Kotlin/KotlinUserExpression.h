//===-- KotlinUserExpression.h -----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_KotlinUserExpression_h_
#define liblldb_KotlinUserExpression_h_

// C Includes
// C++ Includes
#include <memory>
#include <lldb/Expression/LLVMUserExpression.h>

// Other libraries and framework includes
// Project includes
#include "lldb/Expression/ExpressionVariable.h"
#include "lldb/Expression/UserExpression.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/lldb-forward.h"
#include "lldb/lldb-private.h"

namespace lldb_private {
class KotlinParser;

class KotlinPersistentExpressionState : public PersistentExpressionState {
public:
    KotlinPersistentExpressionState();

    ConstString GetNextPersistentVariableName() override;

    void RemovePersistentVariable(lldb::ExpressionVariableSP variable) override;

    lldb::addr_t LookupSymbol(const ConstString &name) override {
        return LLDB_INVALID_ADDRESS;
    }

    static bool classof(const PersistentExpressionState *pv) {
        return pv->getKind() == PersistentExpressionState::eKindKotlin;
    }

private:
    uint32_t m_next_persistent_variable_id; ///< The counter used by
    ///GetNextResultName().
};

//----------------------------------------------------------------------
/// @class KotlinUserExpression KotlinUserExpression.h
/// "lldb/Expression/KotlinUserExpression.h"
/// @brief Encapsulates a single expression for use with Kotlin
///
/// LLDB uses expressions for various purposes, notably to call functions
/// and as a backend for the expr command.  KotlinUserExpression encapsulates
/// the objects needed to parse and interpret an expression.
//----------------------------------------------------------------------
class KotlinUserExpression : public LLVMUserExpression {
public:
    KotlinUserExpression(ExecutionContextScope &exe_scope, llvm::StringRef expr,
                         llvm::StringRef prefix, lldb::LanguageType language,
                         ResultType desired_type,
                         const EvaluateExpressionOptions &options);

    bool Parse(DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
               lldb_private::ExecutionPolicy execution_policy,
               bool keep_result_in_memory, bool generate_debug_info) override;

    bool CanInterpret() override { return true; }
    bool FinalizeJITExecution(
            DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
            lldb::ExpressionVariableSP &result,
            lldb::addr_t function_stack_bottom = LLDB_INVALID_ADDRESS,
            lldb::addr_t function_stack_top = LLDB_INVALID_ADDRESS) override {
        return true;
    }

protected:
    lldb::ExpressionResults
    DoExecute(DiagnosticManager &diagnostic_manager, ExecutionContext &exe_ctx,
              const EvaluateExpressionOptions &options,
              lldb::UserExpressionSP &shared_ptr_to_me,
              lldb::ExpressionVariableSP &result) override;
private:
    void ScanContext(ExecutionContext &exe_ctx,
                             lldb_private::Status &err) override;

    bool AddArguments(ExecutionContext &exe_ctx, std::vector<lldb::addr_t> &args,
                      lldb::addr_t struct_address,
                      DiagnosticManager &diagnostic_manager) override;

    class KotlinInterpreter;
    std::unique_ptr<KotlinInterpreter> m_interpreter;
    Log *m_log;
};

} // namespace lldb_private

#endif // liblldb_KotlinUserExpression_h_