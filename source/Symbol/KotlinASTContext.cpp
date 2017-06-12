//===-- KotlinASTContext.cpp ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Core/ArchSpec.h"
#include "lldb/Core/DumpDataExtractor.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Core/ValueObject.h"
#include "lldb/Expression/DWARFExpression.h"
#include "lldb/Symbol/CompilerType.h"
#include "lldb/Symbol/KotlinASTContext.h"
#include "lldb/Symbol/SymbolFile.h"
#include "lldb/Symbol/Type.h"
#include "lldb/Target/Target.h"
#include "lldb/Utility/Stream.h"

#include "Plugins/ExpressionParser/Kotlin/KotlinUserExpression.h"
#include "Plugins/SymbolFile/DWARF/DWARFASTParserKotlin.h"


using namespace lldb;
using namespace lldb_private;

namespace lldb_private {
class KotlinASTContext::KotlinType {
public:
    enum LLVMCastKind{
        eKindPrimitive,
        eKindObject,
        eKindReference,
        eKindArray,
        eKindFuntionType,
        kNumKinds
    };
    explicit KotlinType(LLVMCastKind kind): m_kind(kind){}
    virtual ~KotlinType() = default;

    virtual ConstString GetName() = 0;

    virtual void Dump(Stream *s) = 0;

    virtual bool IsCompleteType() = 0;
    LLVMCastKind getKind() const { return m_kind; }
private:
    LLVMCastKind m_kind;
};
} // end of lldb_private namespace


namespace {
class KotlinPrimitiveType : public KotlinASTContext::KotlinType {
public:
    enum TypeKind {
        eTypeByte,
        eTypeShort,
        eTypeInt,
        eTypeLong,
        eTypeFloat,
        eTypeDouble,
        eTypeBoolean,
        eTypeChar,
    };

    KotlinPrimitiveType(TypeKind type_kind)
            : KotlinType(KotlinASTContext::KotlinType::eKindPrimitive), m_type_kind(type_kind) {}

    ConstString GetName() override {
        switch (m_type_kind) {
            case eTypeByte:
                return ConstString("kotlin.Byte");
            case eTypeShort:
                return ConstString("kotlin.Short");
            case eTypeInt:
                return ConstString("kotlin.Int");
            case eTypeLong:
                return ConstString("kotlin.Long");
            case eTypeFloat:
                return ConstString("kotlin.Float");
            case eTypeDouble:
                return ConstString("kotlin.Double");
            case eTypeBoolean:
                return ConstString("kotlin.Boolean");
            case eTypeChar:
                return ConstString("kotlin.Char");
        }
        return ConstString();
    }

    TypeKind GetTypeKind() { return m_type_kind; }

    void Dump(Stream *s) override { s->Printf("%s\n", GetName().GetCString()); }

    bool IsCompleteType() override { return true; }

    static bool classof(const KotlinASTContext::KotlinType *jt) {
        return jt->getKind() == KotlinASTContext::KotlinType::eKindPrimitive;
    }

private:
    const TypeKind m_type_kind;
};

class KotlinDynamicType : public KotlinASTContext::KotlinType {
public:
    KotlinDynamicType(LLVMCastKind kind, const ConstString &linkage_name)
            : KotlinType(kind), m_linkage_name(linkage_name),
              m_dynamic_type_id(nullptr) {}

    ConstString GetLinkageName() const { return m_linkage_name; }

    void SetDynamicTypeId(const DWARFExpression &type_id) {
        m_dynamic_type_id = type_id;
    }

    uint64_t CalculateDynamicTypeId(ExecutionContext *exe_ctx,
                                    ValueObject &value_obj) {
        if (!m_dynamic_type_id.IsValid())
            return UINT64_MAX;

        Value obj_load_address = value_obj.GetValue();
        obj_load_address.ResolveValue(exe_ctx);
        obj_load_address.SetValueType(Value::eValueTypeLoadAddress);

        Value result;
        if (m_dynamic_type_id.Evaluate(exe_ctx->GetBestExecutionContextScope(),
                                       nullptr, nullptr, 0, &obj_load_address,
                                       nullptr, result, nullptr)) {
            Status error;

            lldb::addr_t type_id_addr = result.GetScalar().UInt();
            lldb::ProcessSP process_sp = exe_ctx->GetProcessSP();
            if (process_sp)
                return process_sp->ReadUnsignedIntegerFromMemory(
                        type_id_addr, process_sp->GetAddressByteSize(), UINT64_MAX, error);
        }

        return UINT64_MAX;
    }

public:
    ConstString m_linkage_name;
    DWARFExpression m_dynamic_type_id;
};

class KotlinObjectType : public KotlinDynamicType {
public:
    struct Field {
        ConstString m_name;
        CompilerType m_type;
        uint32_t m_offset;
    };

    KotlinObjectType(const ConstString &name, const ConstString &linkage_name,
                   uint32_t byte_size)
            : KotlinDynamicType(KotlinType::eKindObject, linkage_name), m_name(name),
              m_byte_size(byte_size), m_base_class_offset(0), m_is_complete(false) {}

    ConstString GetName() override { return m_name; }

    uint32_t GetByteSize() const { return m_byte_size; }

    uint32_t GetNumFields() { return m_fields.size(); }

    void Dump(Stream *s) override {
        if (m_base_class.IsValid())
            s->Printf("%s : %s\n", GetName().GetCString(),
                      m_base_class.GetTypeName().GetCString());
        else
            s->Printf("%s\n", GetName().GetCString());

        s->IndentMore();
        for (const Field &f : m_fields)
            s->Printf("%s %s\n", f.m_type.GetTypeName().GetCString(),
                      f.m_name.GetCString());
        s->IndentLess();
    }

    Field *GetFieldAtIndex(size_t idx) {
        if (idx < m_fields.size())
            return &m_fields[idx];
        return nullptr;
    }

    CompilerType GetBaseClass() { return m_base_class; }

    uint32_t GetBaseClassOffset() { return m_base_class_offset; }

    uint32_t GetNumInterfaces() { return m_interfaces.size(); }

    CompilerType GetInterfaceAtIndex(uint32_t idx) {
        if (m_interfaces.size() < idx)
            return m_interfaces[idx];
        return CompilerType();
    }

    bool IsCompleteType() override { return m_is_complete; }

    void SetCompleteType(bool is_complete) {
        m_is_complete = is_complete;
        if (m_byte_size == 0) {
            // Try to calcualte the size of the object based on it's values
            for (const Field &field : m_fields) {
                uint32_t field_end = field.m_offset + field.m_type.GetByteSize(nullptr);
                if (field_end > m_byte_size)
                    m_byte_size = field_end;
            }
        }
    }

    void AddBaseClass(const CompilerType &type, uint32_t offset) {
        // TODO: Check if type is an interface and add it to the interface list in
        // that case
        m_base_class = type;
        m_base_class_offset = offset;
    }

    void AddField(const ConstString &name, const CompilerType &type,
                  uint32_t offset) {
        m_fields.push_back({name, type, offset});
    }

    static bool classof(const KotlinASTContext::KotlinType *jt) {
        return jt->getKind() == KotlinASTContext::KotlinType::eKindObject;
    }

private:
    ConstString m_name;
    uint32_t m_byte_size;
    CompilerType m_base_class;
    uint32_t m_base_class_offset;
    std::vector<CompilerType> m_interfaces;
    std::vector<Field> m_fields;
    bool m_is_complete;
};

class KotlinReferenceType : public KotlinASTContext::KotlinType {
public:
    KotlinReferenceType(CompilerType pointee_type)
            : KotlinASTContext::KotlinType(KotlinASTContext::KotlinType::eKindReference), m_pointee_type(pointee_type) {}

    static bool classof(const KotlinASTContext::KotlinType *jt) {
        return jt->getKind() == KotlinASTContext::KotlinType::eKindReference;
    }

    CompilerType GetPointeeType() { return m_pointee_type; }

    ConstString GetName() override {
        ConstString pointee_type_name =
                static_cast<KotlinASTContext::KotlinType *>(GetPointeeType().GetOpaqueQualType())
                        ->GetName();
        return ConstString(std::string(pointee_type_name.AsCString()) + "&");
    }

    void Dump(Stream *s) override {
        static_cast<KotlinASTContext::KotlinType *>(m_pointee_type.GetOpaqueQualType())->Dump(s);
    }

    bool IsCompleteType() override { return m_pointee_type.IsCompleteType(); }

private:
    CompilerType m_pointee_type;
};

class KotlinArrayType : public KotlinDynamicType {
public:
    KotlinArrayType(const ConstString &linkage_name, CompilerType element_type,
                  const DWARFExpression &length_expression,
                  lldb::addr_t data_offset)
            : KotlinDynamicType(KotlinASTContext::KotlinType::eKindArray, linkage_name),
              m_element_type(element_type), m_length_expression(length_expression),
              m_data_offset(data_offset) {}

    static bool classof(const KotlinASTContext::KotlinType *jt) {
        return jt->getKind() == KotlinASTContext::KotlinType::eKindArray;
    }

    CompilerType GetElementType() { return m_element_type; }

    ConstString GetName() override {
        ConstString element_type_name =
                static_cast<KotlinASTContext::KotlinType *>(GetElementType().GetOpaqueQualType())
                        ->GetName();
        return ConstString(std::string(element_type_name.AsCString()) + "[]");
    }

    void Dump(Stream *s) override { s->Printf("%s\n", GetName().GetCString()); }

    bool IsCompleteType() override { return m_length_expression.IsValid(); }

    uint32_t GetNumElements(ValueObject *value_obj) {
        if (!m_length_expression.IsValid())
            return UINT32_MAX;

        Status error;
        ValueObjectSP address_obj = value_obj->AddressOf(error);
        if (error.Fail())
            return UINT32_MAX;

        Value obj_load_address = address_obj->GetValue();
        obj_load_address.SetValueType(Value::eValueTypeLoadAddress);

        Value result;
        ExecutionContextScope *exec_ctx_scope = value_obj->GetExecutionContextRef()
                .Lock(true)
                .GetBestExecutionContextScope();
        if (m_length_expression.Evaluate(exec_ctx_scope, nullptr, nullptr, 0,
                                         nullptr, &obj_load_address, result,
                                         nullptr))
            return result.GetScalar().UInt();

        return UINT32_MAX;
    }

    uint64_t GetElementOffset(size_t idx) {
        return m_data_offset + idx * m_element_type.GetByteSize(nullptr);
    }

private:
    CompilerType m_element_type;
    DWARFExpression m_length_expression;
    lldb::addr_t m_data_offset;
};

class KotlinFunctionType: public KotlinDynamicType {
public:
    KotlinFunctionType(const CompilerType& return_type):KotlinDynamicType(eKindFuntionType, ConstString()),
                             m_return_type(return_type){}
    void AddParameter(const CompilerType& type) { m_parameters.push_back(type);}
    CompilerType GetParameter(unsigned index) const {return m_parameters[index];}
    CompilerType GetReturnType() const { return m_return_type; }
    size_t GetParameterCount() const { return m_parameters.size();}
    void Dump(Stream *s) override {}
    ConstString GetName() override { return ConstString();}
    bool IsCompleteType() override { return true; }

    static bool classof(const KotlinASTContext::KotlinType *jt) {
        return jt->getKind() == KotlinASTContext::KotlinType::eKindFuntionType;
    }
private:
    CompilerType m_return_type;
    std::vector<CompilerType> m_parameters;
};
} // end of anonymous namespace


ConstString KotlinASTContext::GetPluginNameStatic() {
    return ConstString("kotlin");
}

ConstString KotlinASTContext::GetPluginName() {
    return KotlinASTContext::GetPluginNameStatic();
}

uint32_t KotlinASTContext::GetPluginVersion() { return 1; }

lldb::TypeSystemSP KotlinASTContext::CreateInstance(lldb::LanguageType language,
                                                  Module *module,
                                                  Target *target) {
    if (language == eLanguageTypeKotlin) {
        if (module)
            return std::make_shared<KotlinASTContext>(module->GetArchitecture());
        if (target)
            return std::make_shared<KotlinASTContextForExpression>(target->shared_from_this());
        assert(false && "Either a module or a target has to be specifed to create "
                "a KotlinASTContext");
    }
    return lldb::TypeSystemSP();
}

void KotlinASTContext::EnumerateSupportedLanguages(
        std::set<lldb::LanguageType> &languages_for_types,
        std::set<lldb::LanguageType> &languages_for_expressions) {
    static std::vector<lldb::LanguageType> s_languages_for_types(
            {lldb::eLanguageTypeKotlin});
    static std::vector<lldb::LanguageType> s_languages_for_expressions({});

    languages_for_types.insert(s_languages_for_types.begin(),
                               s_languages_for_types.end());
    languages_for_expressions.insert(s_languages_for_expressions.begin(),
                                     s_languages_for_expressions.end());
}

void KotlinASTContext::Initialize() {
    PluginManager::RegisterPlugin(GetPluginNameStatic(), "AST context plug-in",
                                  CreateInstance, EnumerateSupportedLanguages);
}

void KotlinASTContext::Terminate() {
    PluginManager::UnregisterPlugin(CreateInstance);
}

KotlinASTContext::KotlinASTContext(const ArchSpec &arch)
        : TypeSystem(eKindKotlin), m_pointer_byte_size(arch.GetAddressByteSize()) {}

KotlinASTContext::~KotlinASTContext() {}

uint32_t KotlinASTContext::GetPointerByteSize() { return m_pointer_byte_size; }

DWARFASTParser *KotlinASTContext::GetDWARFParser() {
    if (!m_dwarf_ast_parser_ap)
        m_dwarf_ast_parser_ap.reset(new DWARFASTParserKotlin(*this));
    return m_dwarf_ast_parser_ap.get();
}

ConstString KotlinASTContext::DeclGetName(void *opaque_decl) {
    return ConstString();
}

std::vector<CompilerDecl> KotlinASTContext::DeclContextFindDeclByName(
        void *opaque_decl_ctx, ConstString name, const bool ignore_imported_decls) {
    return std::vector<CompilerDecl>();
}

bool KotlinASTContext::DeclContextIsStructUnionOrClass(void *opaque_decl_ctx) {
    return false;
}

ConstString KotlinASTContext::DeclContextGetName(void *opaque_decl_ctx) {
    return ConstString();
}

bool KotlinASTContext::DeclContextIsClassMethod(
        void *opaque_decl_ctx, lldb::LanguageType *language_ptr,
        bool *is_instance_method_ptr, ConstString *language_object_name_ptr) {
    return false;
}

bool KotlinASTContext::IsArrayType(lldb::opaque_compiler_type_t type,
                                 CompilerType *element_type, uint64_t *size,
                                 bool *is_incomplete) {
    if (element_type)
        element_type->Clear();
    if (size)
        *size = 0;
    if (is_incomplete)
        *is_incomplete = false;

    if (KotlinArrayType *array =
                llvm::dyn_cast<KotlinArrayType>(static_cast<KotlinType *>(type))) {
        if (element_type)
            *element_type = array->GetElementType();
        return true;
    }
    return false;
}

bool KotlinASTContext::IsAggregateType(lldb::opaque_compiler_type_t type) {
    return llvm::isa<KotlinObjectType>(static_cast<KotlinType *>(type));
}

bool KotlinASTContext::IsCharType(lldb::opaque_compiler_type_t type) {
    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type)))
        return ptype->GetTypeKind() == KotlinPrimitiveType::eTypeChar;
    return false;
}

bool KotlinASTContext::IsFloatingPointType(lldb::opaque_compiler_type_t type,
                                         uint32_t &count, bool &is_complex) {
    is_complex = true;

    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type))) {
        switch (ptype->GetTypeKind()) {
            case KotlinPrimitiveType::eTypeFloat:
            case KotlinPrimitiveType::eTypeDouble:
                count = 1;
                return true;
            default:
                break;
        }
    }

    count = 0;
    return false;
}

bool KotlinASTContext::IsFunctionType(lldb::opaque_compiler_type_t type,
                                    bool *is_variadic_ptr) {
    if (is_variadic_ptr)
        *is_variadic_ptr = false;
    return llvm::isa<KotlinFunctionType>(static_cast<KotlinType *>(type));
}

size_t KotlinASTContext::GetNumberOfFunctionArguments(
        lldb::opaque_compiler_type_t type) {
    return llvm::dyn_cast<KotlinFunctionType>(static_cast<KotlinType *>(type))->GetParameterCount();
}

CompilerType
KotlinASTContext::GetFunctionArgumentAtIndex(lldb::opaque_compiler_type_t type,
                                           const size_t index) {
    return CompilerType();
}

bool KotlinASTContext::IsFunctionPointerType(lldb::opaque_compiler_type_t type) {
    return false;
}

bool KotlinASTContext::IsBlockPointerType(
        lldb::opaque_compiler_type_t type,
        CompilerType *function_pointer_type_ptr) {
    return false;
}

bool KotlinASTContext::IsIntegerType(lldb::opaque_compiler_type_t type,
                                   bool &is_signed) {
    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type))) {
        switch (ptype->GetTypeKind()) {
            case KotlinPrimitiveType::eTypeByte:
            case KotlinPrimitiveType::eTypeShort:
            case KotlinPrimitiveType::eTypeInt:
            case KotlinPrimitiveType::eTypeLong:
                is_signed = true;
                return true;
            default:
                break;
        }
    }

    is_signed = false;
    return false;
}

bool KotlinASTContext::IsPossibleDynamicType(lldb::opaque_compiler_type_t type,
                                           CompilerType *target_type,
                                           bool check_cplusplus,
                                           bool check_objc) {
    return llvm::isa<KotlinReferenceType>(static_cast<KotlinType *>(type));
}

bool KotlinASTContext::IsPointerType(lldb::opaque_compiler_type_t type,
                                   CompilerType *pointee_type) {
    if (pointee_type)
        pointee_type->Clear();
    return false;
}

bool KotlinASTContext::IsReferenceType(lldb::opaque_compiler_type_t type,
                                     CompilerType *pointee_type,
                                     bool *is_rvalue) {
    if (is_rvalue)
        *is_rvalue = false;

    if (KotlinReferenceType *ref =
                llvm::dyn_cast<KotlinReferenceType>(static_cast<KotlinType *>(type))) {
        if (pointee_type)
            *pointee_type = ref->GetPointeeType();
        return true;
    }

    if (pointee_type)
        pointee_type->Clear();
    return false;
}

bool KotlinASTContext::IsScalarType(lldb::opaque_compiler_type_t type) {
    return llvm::isa<KotlinReferenceType>(static_cast<KotlinType *>(type)) ||
           llvm::isa<KotlinPrimitiveType>(static_cast<KotlinType *>(type));
}

bool KotlinASTContext::IsVoidType(lldb::opaque_compiler_type_t type) {
    return false; // TODO: Implement if we introduce the void type
}

bool KotlinASTContext::SupportsLanguage(lldb::LanguageType language) {
    return language == lldb::eLanguageTypeKotlin;
}

bool KotlinASTContext::IsRuntimeGeneratedType(lldb::opaque_compiler_type_t type) {
    return true;
}

bool KotlinASTContext::IsPointerOrReferenceType(lldb::opaque_compiler_type_t type,
                                              CompilerType *pointee_type) {
    return IsPointerType(type, pointee_type) ||
           IsReferenceType(type, pointee_type);
}

bool KotlinASTContext::IsCStringType(lldb::opaque_compiler_type_t type,
                                   uint32_t &length) {
    return false; // TODO: Implement it if we need it for string literals
}

bool KotlinASTContext::IsTypedefType(lldb::opaque_compiler_type_t type) {
    return false;
}

bool KotlinASTContext::IsVectorType(lldb::opaque_compiler_type_t type,
                                  CompilerType *element_type, uint64_t *size) {
    if (element_type)
        element_type->Clear();
    if (size)
        *size = 0;
    return false;
}

bool KotlinASTContext::IsPolymorphicClass(lldb::opaque_compiler_type_t type) {
    return llvm::isa<KotlinObjectType>(static_cast<KotlinType *>(type));
}

uint32_t
KotlinASTContext::IsHomogeneousAggregate(lldb::opaque_compiler_type_t type,
                                       CompilerType *base_type_ptr) {
    return false;
}

bool KotlinASTContext::IsCompleteType(lldb::opaque_compiler_type_t type) {
    return static_cast<KotlinType *>(type)->IsCompleteType();
}

bool KotlinASTContext::IsConst(lldb::opaque_compiler_type_t type) {
    return false;
}

bool KotlinASTContext::IsBeingDefined(lldb::opaque_compiler_type_t type) {
    return false;
}

bool KotlinASTContext::IsDefined(lldb::opaque_compiler_type_t type) {
    return IsCompleteType(type);
}

bool KotlinASTContext::GetCompleteType(lldb::opaque_compiler_type_t type) {
    if (IsCompleteType(type))
        return true;

    if (KotlinArrayType *array =
                llvm::dyn_cast<KotlinArrayType>(static_cast<KotlinType *>(type)))
        return GetCompleteType(array->GetElementType().GetOpaqueQualType());

    if (KotlinReferenceType *reference =
                llvm::dyn_cast<KotlinReferenceType>(static_cast<KotlinType *>(type)))
        return GetCompleteType(reference->GetPointeeType().GetOpaqueQualType());

    if (llvm::isa<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        SymbolFile *symbol_file = GetSymbolFile();
        if (!symbol_file)
            return false;

        CompilerType object_type(this, type);
        return symbol_file->CompleteType(object_type);
    }
    return false;
}

ConstString KotlinASTContext::GetTypeName(lldb::opaque_compiler_type_t type) {
    if (type)
        return static_cast<KotlinType *>(type)->GetName();
    return ConstString();
}

uint32_t
KotlinASTContext::GetTypeInfo(lldb::opaque_compiler_type_t type,
                            CompilerType *pointee_or_element_compiler_type) {
    if (pointee_or_element_compiler_type)
        pointee_or_element_compiler_type->Clear();
    if (!type)
        return 0;

    if (IsReferenceType(type, pointee_or_element_compiler_type))
        return eTypeHasChildren | eTypeHasValue | eTypeIsReference;
    if (IsArrayType(type, pointee_or_element_compiler_type, nullptr, nullptr))
        return eTypeHasChildren | eTypeIsArray;
    if (llvm::isa<KotlinObjectType>(static_cast<KotlinType *>(type)))
        return eTypeHasChildren | eTypeIsClass;

    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type))) {
        switch (ptype->GetTypeKind()) {
            case KotlinPrimitiveType::eTypeByte:
            case KotlinPrimitiveType::eTypeShort:
            case KotlinPrimitiveType::eTypeInt:
            case KotlinPrimitiveType::eTypeLong:
                return eTypeHasValue | eTypeIsBuiltIn | eTypeIsScalar | eTypeIsInteger |
                       eTypeIsSigned;
            case KotlinPrimitiveType::eTypeFloat:
            case KotlinPrimitiveType::eTypeDouble:
                return eTypeHasValue | eTypeIsBuiltIn | eTypeIsScalar | eTypeIsFloat |
                       eTypeIsSigned;
            case KotlinPrimitiveType::eTypeBoolean:
                return eTypeHasValue | eTypeIsBuiltIn | eTypeIsScalar;
            case KotlinPrimitiveType::eTypeChar:
                return eTypeHasValue | eTypeIsBuiltIn | eTypeIsScalar;
        }
    }
    return 0;
}

lldb::TypeClass
KotlinASTContext::GetTypeClass(lldb::opaque_compiler_type_t type) {
    if (!type)
        return eTypeClassInvalid;
    if (llvm::isa<KotlinReferenceType>(static_cast<KotlinType *>(type)))
        return eTypeClassReference;
    if (llvm::isa<KotlinArrayType>(static_cast<KotlinType *>(type)))
        return eTypeClassArray;
    if (llvm::isa<KotlinObjectType>(static_cast<KotlinType *>(type)))
        return eTypeClassClass;
    if (llvm::isa<KotlinPrimitiveType>(static_cast<KotlinType *>(type)))
        return eTypeClassBuiltin;
    assert(false && "Kotlin type with unhandled type class");
    return eTypeClassInvalid;
}

lldb::LanguageType
KotlinASTContext::GetMinimumLanguage(lldb::opaque_compiler_type_t type) {
    return lldb::eLanguageTypeKotlin;
}

CompilerType
KotlinASTContext::GetArrayElementType(lldb::opaque_compiler_type_t type,
                                    uint64_t *stride) {
    if (stride)
        *stride = 0;

    CompilerType element_type;
    if (IsArrayType(type, &element_type, nullptr, nullptr))
        return element_type;
    return CompilerType();
}

CompilerType KotlinASTContext::GetPointeeType(lldb::opaque_compiler_type_t type) {
    CompilerType pointee_type;
    if (IsPointerType(type, &pointee_type))
        return pointee_type;
    return CompilerType();
}

CompilerType KotlinASTContext::GetPointerType(lldb::opaque_compiler_type_t type) {
    return CompilerType(); // No pointer types in Kotlin
}

CompilerType
KotlinASTContext::GetCanonicalType(lldb::opaque_compiler_type_t type) {
    return CompilerType(this, type);
}

CompilerType
KotlinASTContext::GetFullyUnqualifiedType(lldb::opaque_compiler_type_t type) {
    return CompilerType(this, type);
}

CompilerType
KotlinASTContext::GetNonReferenceType(lldb::opaque_compiler_type_t type) {
    CompilerType pointee_type;
    if (IsReferenceType(type, &pointee_type))
        return pointee_type;
    return CompilerType(this, type);
}

CompilerType
KotlinASTContext::GetTypedefedType(lldb::opaque_compiler_type_t type) {
    return CompilerType();
}

CompilerType KotlinASTContext::GetBasicTypeFromAST(lldb::BasicType basic_type) {
    return CompilerType();
}

CompilerType
KotlinASTContext::GetBuiltinTypeForEncodingAndBitSize(lldb::Encoding encoding,
                                                    size_t bit_size) {
    return CompilerType();
}

size_t KotlinASTContext::GetTypeBitAlign(lldb::opaque_compiler_type_t type) {
    return 0;
}

lldb::BasicType
KotlinASTContext::GetBasicTypeEnumeration(lldb::opaque_compiler_type_t type) {
    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type))) {
        switch (ptype->GetTypeKind()) {
            case KotlinPrimitiveType::eTypeByte:
                return eBasicTypeOther;
            case KotlinPrimitiveType::eTypeShort:
                return eBasicTypeShort;
            case KotlinPrimitiveType::eTypeInt:
                return eBasicTypeInt;
            case KotlinPrimitiveType::eTypeLong:
                return eBasicTypeLong;
            case KotlinPrimitiveType::eTypeFloat:
                return eBasicTypeFloat;
            case KotlinPrimitiveType::eTypeDouble:
                return eBasicTypeDouble;
            case KotlinPrimitiveType::eTypeBoolean:
                return eBasicTypeBool;
            case KotlinPrimitiveType::eTypeChar:
                return eBasicTypeChar;
        }
    }
    return eBasicTypeInvalid;
}

uint64_t KotlinASTContext::GetBitSize(lldb::opaque_compiler_type_t type,
                                    ExecutionContextScope *exe_scope) {
    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type))) {
        switch (ptype->GetTypeKind()) {
            case KotlinPrimitiveType::eTypeByte:
                return 8;
            case KotlinPrimitiveType::eTypeShort:
                return 16;
            case KotlinPrimitiveType::eTypeInt:
                return 32;
            case KotlinPrimitiveType::eTypeLong:
                return 64;
            case KotlinPrimitiveType::eTypeFloat:
                return 32;
            case KotlinPrimitiveType::eTypeDouble:
                return 64;
            case KotlinPrimitiveType::eTypeBoolean:
                return 1;
            case KotlinPrimitiveType::eTypeChar:
                return 16;
        }
    } else if (llvm::isa<KotlinReferenceType>(static_cast<KotlinType *>(type))) {
        return 32; // References are always 4 byte long in Kotlin
    } else if (llvm::isa<KotlinArrayType>(static_cast<KotlinType *>(type))) {
        return 64;
    } else if (KotlinObjectType *obj = llvm::dyn_cast<KotlinObjectType>(
            static_cast<KotlinType *>(type))) {
        return obj->GetByteSize() * 8;
    }
    return 0;
}

lldb::Encoding KotlinASTContext::GetEncoding(lldb::opaque_compiler_type_t type,
                                           uint64_t &count) {
    count = 1;

    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type))) {
        switch (ptype->GetTypeKind()) {
            case KotlinPrimitiveType::eTypeByte:
            case KotlinPrimitiveType::eTypeShort:
            case KotlinPrimitiveType::eTypeInt:
            case KotlinPrimitiveType::eTypeLong:
                return eEncodingSint;
            case KotlinPrimitiveType::eTypeFloat:
            case KotlinPrimitiveType::eTypeDouble:
                return eEncodingIEEE754;
            case KotlinPrimitiveType::eTypeBoolean:
            case KotlinPrimitiveType::eTypeChar:
                return eEncodingUint;
        }
    }
    if (IsReferenceType(type))
        return eEncodingUint;
    return eEncodingInvalid;
}

lldb::Format KotlinASTContext::GetFormat(lldb::opaque_compiler_type_t type) {
    if (KotlinPrimitiveType *ptype =
                llvm::dyn_cast<KotlinPrimitiveType>(static_cast<KotlinType *>(type))) {
        switch (ptype->GetTypeKind()) {
            case KotlinPrimitiveType::eTypeByte:
            case KotlinPrimitiveType::eTypeShort:
            case KotlinPrimitiveType::eTypeInt:
            case KotlinPrimitiveType::eTypeLong:
                return eFormatDecimal;
            case KotlinPrimitiveType::eTypeFloat:
            case KotlinPrimitiveType::eTypeDouble:
                return eFormatFloat;
            case KotlinPrimitiveType::eTypeBoolean:
                return eFormatBoolean;
            case KotlinPrimitiveType::eTypeChar:
                return eFormatUnicode16;
        }
    }
    if (IsReferenceType(type))
        return eFormatHex;
    return eFormatDefault;
}

unsigned KotlinASTContext::GetTypeQualifiers(lldb::opaque_compiler_type_t type) {
    return 0;
}

size_t
KotlinASTContext::ConvertStringToFloatValue(lldb::opaque_compiler_type_t type,
                                          const char *s, uint8_t *dst,
                                          size_t dst_size) {
    assert(false && "Not implemented");
    return 0;
}

size_t
KotlinASTContext::GetNumTemplateArguments(lldb::opaque_compiler_type_t type) {
    return 0;
}

CompilerType
KotlinASTContext::GetTemplateArgument(lldb::opaque_compiler_type_t type,
                                    size_t idx,
                                    lldb::TemplateArgumentKind &kind) {
    return CompilerType();
}

uint32_t KotlinASTContext::GetNumFields(lldb::opaque_compiler_type_t type) {
    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);
        return obj->GetNumFields();
    }
    return 0;
}

CompilerType KotlinASTContext::GetFieldAtIndex(lldb::opaque_compiler_type_t type,
                                             size_t idx, std::string &name,
                                             uint64_t *bit_offset_ptr,
                                             uint32_t *bitfield_bit_size_ptr,
                                             bool *is_bitfield_ptr) {
    if (bit_offset_ptr)
        *bit_offset_ptr = 0;
    if (bitfield_bit_size_ptr)
        *bitfield_bit_size_ptr = 0;
    if (is_bitfield_ptr)
        *is_bitfield_ptr = false;

    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);

        KotlinObjectType::Field *field = obj->GetFieldAtIndex(idx);
        if (!field)
            return CompilerType();
        name = field->m_name.AsCString();
        if (bit_offset_ptr)
            *bit_offset_ptr = field->m_offset * 8;
        return field->m_type;
    }
    return CompilerType();
}

uint32_t KotlinASTContext::GetNumChildren(lldb::opaque_compiler_type_t type,
                                        bool omit_empty_base_classes) {
    GetCompleteType(type);

    if (KotlinReferenceType *ref =
                llvm::dyn_cast<KotlinReferenceType>(static_cast<KotlinType *>(type)))
        return ref->GetPointeeType().GetNumChildren(omit_empty_base_classes);

    if (llvm::isa<KotlinObjectType>(static_cast<KotlinType *>(type)))
        return GetNumFields(type) + GetNumDirectBaseClasses(type);

    return 0;
}

uint32_t
KotlinASTContext::GetNumDirectBaseClasses(lldb::opaque_compiler_type_t type) {
    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);
        return obj->GetNumInterfaces() + (obj->GetBaseClass() ? 1 : 0);
    }
    return 0;
}

uint32_t
KotlinASTContext::GetNumVirtualBaseClasses(lldb::opaque_compiler_type_t type) {
    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);
        return obj->GetNumInterfaces();
    }
    return 0;
}

CompilerType KotlinASTContext::GetDirectBaseClassAtIndex(
        lldb::opaque_compiler_type_t type, size_t idx, uint32_t *bit_offset_ptr) {
    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);

        if (CompilerType base_class = obj->GetBaseClass()) {
            if (idx == 0)
                return base_class;
            else
                --idx;
        }
        return obj->GetInterfaceAtIndex(idx);
    }
    return CompilerType();
}

CompilerType KotlinASTContext::GetVirtualBaseClassAtIndex(
        lldb::opaque_compiler_type_t type, size_t idx, uint32_t *bit_offset_ptr) {
    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);
        return obj->GetInterfaceAtIndex(idx);
    }
    return CompilerType();
}

void KotlinASTContext::DumpValue(
        lldb::opaque_compiler_type_t type, ExecutionContext *exe_ctx, Stream *s,
        lldb::Format format, const DataExtractor &data, lldb::offset_t data_offset,
        size_t data_byte_size, uint32_t bitfield_bit_size,
        uint32_t bitfield_bit_offset, bool show_types, bool show_summary,
        bool verbose, uint32_t depth) {
    assert(false && "Not implemented");
}

bool KotlinASTContext::DumpTypeValue(
        lldb::opaque_compiler_type_t type, Stream *s, lldb::Format format,
        const DataExtractor &data, lldb::offset_t data_offset,
        size_t data_byte_size, uint32_t bitfield_bit_size,
        uint32_t bitfield_bit_offset, ExecutionContextScope *exe_scope) {
    if (IsScalarType(type)) {
        return DumpDataExtractor(data, s, data_offset, format, data_byte_size,
                                 1, // count
                                 UINT32_MAX, LLDB_INVALID_ADDRESS,
                                 bitfield_bit_size, bitfield_bit_offset, exe_scope);
    }
    return false;
}

void KotlinASTContext::DumpTypeDescription(lldb::opaque_compiler_type_t type) {
    StreamFile s(stdout, false);
    DumpTypeDescription(type, &s);
}

void KotlinASTContext::DumpTypeDescription(lldb::opaque_compiler_type_t type,
                                         Stream *s) {
    static_cast<KotlinType *>(type)->Dump(s);
}

void KotlinASTContext::DumpSummary(lldb::opaque_compiler_type_t type,
                                 ExecutionContext *exe_ctx, Stream *s,
                                 const DataExtractor &data,
                                 lldb::offset_t data_offset,
                                 size_t data_byte_size) {
    assert(false && "Not implemented");
}

int KotlinASTContext::GetFunctionArgumentCount(
        lldb::opaque_compiler_type_t type) {
    return 0;
}

CompilerType KotlinASTContext::GetFunctionArgumentTypeAtIndex(
        lldb::opaque_compiler_type_t type, size_t idx) {
    return CompilerType();
}

CompilerType
KotlinASTContext::GetFunctionReturnType(lldb::opaque_compiler_type_t type) {
    return CompilerType();
}

size_t
KotlinASTContext::GetNumMemberFunctions(lldb::opaque_compiler_type_t type) {
    return 0;
}

TypeMemberFunctionImpl
KotlinASTContext::GetMemberFunctionAtIndex(lldb::opaque_compiler_type_t type,
                                         size_t idx) {
    return TypeMemberFunctionImpl();
}

CompilerType KotlinASTContext::GetChildCompilerTypeAtIndex(
        lldb::opaque_compiler_type_t type, ExecutionContext *exe_ctx, size_t idx,
        bool transparent_pointers, bool omit_empty_base_classes,
        bool ignore_array_bounds, std::string &child_name,
        uint32_t &child_byte_size, int32_t &child_byte_offset,
        uint32_t &child_bitfield_bit_size, uint32_t &child_bitfield_bit_offset,
        bool &child_is_base_class, bool &child_is_deref_of_parent,
        ValueObject *valobj, uint64_t &language_flags) {
    child_name.clear();
    child_byte_size = 0;
    child_byte_offset = 0;
    child_bitfield_bit_size = 0;
    child_bitfield_bit_offset = 0;
    child_is_base_class = false;
    child_is_deref_of_parent = false;
    language_flags = 0;

    ExecutionContextScope *exec_ctx_scope =
            exe_ctx ? exe_ctx->GetBestExecutionContextScope() : nullptr;

    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);

        if (CompilerType base_class = obj->GetBaseClass()) {
            if (idx == 0) {
                KotlinType *base_class_type =
                        static_cast<KotlinType *>(base_class.GetOpaqueQualType());
                child_name = base_class_type->GetName().GetCString();
                child_byte_size = base_class.GetByteSize(
                        exe_ctx ? exe_ctx->GetBestExecutionContextScope() : nullptr);
                child_byte_offset = obj->GetBaseClassOffset();
                child_is_base_class = true;
                return base_class;
            }
            idx -= 1;
        }

        KotlinObjectType::Field *field = obj->GetFieldAtIndex(idx);
        if (!field)
            return CompilerType();

        child_name = field->m_name.AsCString();
        child_byte_size = field->m_type.GetByteSize(exec_ctx_scope);
        child_byte_offset = field->m_offset;
        return field->m_type;
    } else if (KotlinReferenceType *ref = llvm::dyn_cast<KotlinReferenceType>(
            static_cast<KotlinType *>(type))) {
        CompilerType pointee_type = ref->GetPointeeType();

        if (transparent_pointers)
            return pointee_type.GetChildCompilerTypeAtIndex(
                    exe_ctx, idx, transparent_pointers, omit_empty_base_classes,
                    ignore_array_bounds, child_name, child_byte_size, child_byte_offset,
                    child_bitfield_bit_size, child_bitfield_bit_offset,
                    child_is_base_class, child_is_deref_of_parent, valobj,
                    language_flags);

        if (idx != 0)
            return CompilerType();

        if (valobj && valobj->GetName())
            child_name = valobj->GetName().GetCString();
        child_is_deref_of_parent = true;
        child_byte_offset = 0;
        child_byte_size = pointee_type.GetByteSize(exec_ctx_scope);
        return pointee_type;
    }
    return CompilerType();
}

uint32_t
KotlinASTContext::GetIndexOfChildWithName(lldb::opaque_compiler_type_t type,
                                        const char *name,
                                        bool omit_empty_base_classes) {
    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);

        uint32_t index_offset = 0;
        if (CompilerType base_class = obj->GetBaseClass()) {
            if (base_class.GetTypeName() == ConstString(name))
                return 0;
            index_offset = 1;
        }
        for (uint32_t i = 0; i < obj->GetNumFields(); ++i) {
            if (obj->GetFieldAtIndex(i)->m_name == ConstString(name))
                return i + index_offset;
        }
    } else if (KotlinReferenceType *ref = llvm::dyn_cast<KotlinReferenceType>(
            static_cast<KotlinType *>(type))) {
        return GetIndexOfChildWithName(ref->GetPointeeType().GetOpaqueQualType(),
                                       name, omit_empty_base_classes);
    }
    return UINT_MAX;
}

size_t KotlinASTContext::GetIndexOfChildMemberWithName(
        lldb::opaque_compiler_type_t type, const char *name,
        bool omit_empty_base_classes, std::vector<uint32_t> &child_indexes) {
    child_indexes.clear();

    if (KotlinObjectType *obj =
                llvm::dyn_cast<KotlinObjectType>(static_cast<KotlinType *>(type))) {
        GetCompleteType(type);

        uint32_t index_offset = 0;
        if (CompilerType base_class = obj->GetBaseClass()) {
            if (GetIndexOfChildMemberWithName(base_class.GetOpaqueQualType(), name,
                                              omit_empty_base_classes,
                                              child_indexes) != 0) {
                child_indexes.insert(child_indexes.begin(), 0);
                return child_indexes.size();
            }
            index_offset = 1;
        }

        for (uint32_t i = 0; i < obj->GetNumFields(); ++i) {
            if (obj->GetFieldAtIndex(i)->m_name == ConstString(name)) {
                child_indexes.push_back(i + index_offset);
                return child_indexes.size();
            }
        }
    } else if (KotlinReferenceType *ref = llvm::dyn_cast<KotlinReferenceType>(
            static_cast<KotlinType *>(type))) {
        return GetIndexOfChildMemberWithName(
                ref->GetPointeeType().GetOpaqueQualType(), name,
                omit_empty_base_classes, child_indexes);
    }
    return 0;
}

CompilerType
KotlinASTContext::GetLValueReferenceType(lldb::opaque_compiler_type_t type) {
    return CreateReferenceType(CompilerType(this, type));
}

ConstString KotlinASTContext::DeclContextGetScopeQualifiedName(
        lldb::opaque_compiler_type_t opaque_decl_ctx) {
    return GetTypeName(opaque_decl_ctx);
}

static void AddPrimitiveType(KotlinASTContext::KotlinTypeMap &type_map,
                             KotlinPrimitiveType::TypeKind type_kind) {
    KotlinPrimitiveType *type = new KotlinPrimitiveType(type_kind);
    type_map.emplace(type->GetName(),
                     std::unique_ptr<KotlinASTContext::KotlinType>(type));
}

CompilerType KotlinASTContext::CreateBaseType(const ConstString &name) {
    if (m_base_type_map.empty()) {
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeByte);
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeShort);
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeInt);
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeLong);
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeFloat);
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeDouble);
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeBoolean);
        AddPrimitiveType(m_base_type_map, KotlinPrimitiveType::eTypeChar);
    }
    auto it = m_base_type_map.find(name);
    if (it != m_base_type_map.end())
        return CompilerType(this, it->second.get());
    return CompilerType();
}

CompilerType KotlinASTContext::CreateObjectType(const ConstString &name,
                                              const ConstString &linkage_name,
                                              uint32_t byte_size) {
    auto it = m_object_type_map.find(name);
    if (it == m_object_type_map.end()) {
        std::unique_ptr<KotlinType> object_type(
                new KotlinObjectType(name, linkage_name, byte_size));
        it = m_object_type_map.emplace(name, std::move(object_type)).first;
    }
    return CompilerType(this, it->second.get());
}

CompilerType KotlinASTContext::CreateArrayType(
        const ConstString &linkage_name, const CompilerType &element_type,
        const DWARFExpression &length_expression, const lldb::addr_t data_offset) {
    ConstString name = element_type.GetTypeName();
    auto it = m_array_type_map.find(name);
    if (it == m_array_type_map.end()) {
        std::unique_ptr<KotlinType> array_type(new KotlinArrayType(
                linkage_name, element_type, length_expression, data_offset));
        it = m_array_type_map.emplace(name, std::move(array_type)).first;
    }
    return CompilerType(this, it->second.get());
}

CompilerType
KotlinASTContext::CreateReferenceType(const CompilerType &pointee_type) {
    ConstString name = pointee_type.GetTypeName();
    auto it = m_reference_type_map.find(name);
    if (it == m_reference_type_map.end())
        it = m_reference_type_map
                .emplace(name, std::unique_ptr<KotlinType>(
                        new KotlinReferenceType(pointee_type)))
                .first;
    return CompilerType(this, it->second.get());
}

void KotlinASTContext::CompleteObjectType(const CompilerType &object_type) {
    KotlinObjectType *obj = llvm::dyn_cast<KotlinObjectType>(
            static_cast<KotlinType *>(object_type.GetOpaqueQualType()));
    assert(obj &&
                   "KotlinASTContext::CompleteObjectType called with not a KotlinObjectType");
    obj->SetCompleteType(true);
}

void KotlinASTContext::AddBaseClassToObject(const CompilerType &object_type,
                                          const CompilerType &member_type,
                                          uint32_t member_offset) {
    KotlinObjectType *obj = llvm::dyn_cast<KotlinObjectType>(
            static_cast<KotlinType *>(object_type.GetOpaqueQualType()));
    assert(obj &&
                   "KotlinASTContext::AddMemberToObject called with not a KotlinObjectType");
    obj->AddBaseClass(member_type, member_offset);
}

void KotlinASTContext::AddMemberToObject(const CompilerType &object_type,
                                       const ConstString &name,
                                       const CompilerType &member_type,
                                       uint32_t member_offset) {
    KotlinObjectType *obj = llvm::dyn_cast<KotlinObjectType>(
            static_cast<KotlinType *>(object_type.GetOpaqueQualType()));
    assert(obj &&
                   "KotlinASTContext::AddMemberToObject called with not a KotlinObjectType");
    obj->AddField(name, member_type, member_offset);
}

void KotlinASTContext::SetDynamicTypeId(const CompilerType &type,
                                      const DWARFExpression &type_id) {
    KotlinObjectType *obj = llvm::dyn_cast<KotlinObjectType>(
            static_cast<KotlinType *>(type.GetOpaqueQualType()));
    assert(obj &&
                   "KotlinASTContext::SetDynamicTypeId called with not a KotlinObjectType");
    obj->SetDynamicTypeId(type_id);
}


CompilerType KotlinASTContext::CreateFunctionType(const CompilerType& return_type, const CompilerType* parameters, unsigned num_parameters, bool& is_variadic) {
    auto func = new KotlinFunctionType(return_type);
    for (unsigned i = 0; i < num_parameters; ++i) {
        func->AddParameter(parameters[i]);
    }
    return CompilerType(this, func);
}


uint64_t KotlinASTContext::CalculateDynamicTypeId(ExecutionContext *exe_ctx,
                                                const CompilerType &type,
                                                ValueObject &in_value) {
    if (KotlinObjectType *obj = llvm::dyn_cast<KotlinObjectType>(
            static_cast<KotlinType *>(type.GetOpaqueQualType())))
        return obj->CalculateDynamicTypeId(exe_ctx, in_value);
    if (KotlinArrayType *arr = llvm::dyn_cast<KotlinArrayType>(
            static_cast<KotlinType *>(type.GetOpaqueQualType())))
        return arr->CalculateDynamicTypeId(exe_ctx, in_value);
    return UINT64_MAX;
}

uint32_t KotlinASTContext::CalculateArraySize(const CompilerType &type,
                                            ValueObject &in_value) {
    if (KotlinArrayType *arr = llvm::dyn_cast<KotlinArrayType>(
            static_cast<KotlinType *>(type.GetOpaqueQualType())))
        return arr->GetNumElements(&in_value);
    return UINT32_MAX;
}

uint64_t KotlinASTContext::CalculateArrayElementOffset(const CompilerType &type,
                                                     size_t index) {
    if (KotlinArrayType *arr = llvm::dyn_cast<KotlinArrayType>(
            static_cast<KotlinType *>(type.GetOpaqueQualType())))
        return arr->GetElementOffset(index);
    return UINT64_MAX;
}

ConstString KotlinASTContext::GetLinkageName(const CompilerType &type) {
    if (KotlinObjectType *obj = llvm::dyn_cast<KotlinObjectType>(
            static_cast<KotlinType *>(type.GetOpaqueQualType())))
        return obj->GetLinkageName();
    return ConstString();
}

KotlinASTContextForExpression::KotlinASTContextForExpression(TargetSP target)
        :KotlinASTContext(target->GetArchitecture()), m_target_wp(target) {}

UserExpression *KotlinASTContextForExpression::GetUserExpression(
        llvm::StringRef expr, llvm::StringRef prefix, lldb::LanguageType language,
        Expression::ResultType desired_type,
        const EvaluateExpressionOptions &options) {
    TargetSP target = m_target_wp.lock();
    if (target)
        return new KotlinUserExpression(*target, expr, prefix, language, desired_type,
                                       options);
    return nullptr;
}