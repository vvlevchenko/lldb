//===-- SBModuleSpec.cpp ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/API/SBModuleSpec.h"
#include "Utils.h"
#include "lldb/API/SBStream.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/ModuleSpec.h"
#include "lldb/Host/Host.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Utility/Stream.h"

using namespace lldb;
using namespace lldb_private;

SBModuleSpec::SBModuleSpec() : m_opaque_up(new lldb_private::ModuleSpec()) {}

SBModuleSpec::SBModuleSpec(const SBModuleSpec &rhs) : m_opaque_up() {
  m_opaque_up = clone(rhs.m_opaque_up);
}

const SBModuleSpec &SBModuleSpec::operator=(const SBModuleSpec &rhs) {
  if (this != &rhs)
    m_opaque_up = clone(rhs.m_opaque_up);
  return *this;
}

SBModuleSpec::~SBModuleSpec() {}

bool SBModuleSpec::IsValid() const { return m_opaque_up->operator bool(); }

void SBModuleSpec::Clear() { m_opaque_up->Clear(); }

SBFileSpec SBModuleSpec::GetFileSpec() {
  SBFileSpec sb_spec(m_opaque_up->GetFileSpec());
  return sb_spec;
}

void SBModuleSpec::SetFileSpec(const lldb::SBFileSpec &sb_spec) {
  m_opaque_up->GetFileSpec() = *sb_spec;
}

lldb::SBFileSpec SBModuleSpec::GetPlatformFileSpec() {
  return SBFileSpec(m_opaque_up->GetPlatformFileSpec());
}

void SBModuleSpec::SetPlatformFileSpec(const lldb::SBFileSpec &sb_spec) {
  m_opaque_up->GetPlatformFileSpec() = *sb_spec;
}

lldb::SBFileSpec SBModuleSpec::GetSymbolFileSpec() {
  return SBFileSpec(m_opaque_up->GetSymbolFileSpec());
}

void SBModuleSpec::SetSymbolFileSpec(const lldb::SBFileSpec &sb_spec) {
  m_opaque_up->GetSymbolFileSpec() = *sb_spec;
}

const char *SBModuleSpec::GetObjectName() {
  return m_opaque_up->GetObjectName().GetCString();
}

void SBModuleSpec::SetObjectName(const char *name) {
  m_opaque_up->GetObjectName().SetCString(name);
}

const char *SBModuleSpec::GetTriple() {
  std::string triple(m_opaque_up->GetArchitecture().GetTriple().str());
  // Unique the string so we don't run into ownership issues since the const
  // strings put the string into the string pool once and the strings never
  // comes out
  ConstString const_triple(triple.c_str());
  return const_triple.GetCString();
}

void SBModuleSpec::SetTriple(const char *triple) {
  m_opaque_up->GetArchitecture().SetTriple(triple);
}

const uint8_t *SBModuleSpec::GetUUIDBytes() {
  return m_opaque_up->GetUUID().GetBytes().data();
}

size_t SBModuleSpec::GetUUIDLength() {
  return m_opaque_up->GetUUID().GetBytes().size();
}

bool SBModuleSpec::SetUUIDBytes(const uint8_t *uuid, size_t uuid_len) {
  m_opaque_up->GetUUID() = UUID::fromOptionalData(uuid, uuid_len);
  return m_opaque_up->GetUUID().IsValid();
}

bool SBModuleSpec::GetDescription(lldb::SBStream &description) {
  m_opaque_up->Dump(description.ref());
  return true;
}

SBModuleSpecList::SBModuleSpecList() : m_opaque_up(new ModuleSpecList()) {}

SBModuleSpecList::SBModuleSpecList(const SBModuleSpecList &rhs)
    : m_opaque_up(new ModuleSpecList(*rhs.m_opaque_up)) {}

SBModuleSpecList &SBModuleSpecList::operator=(const SBModuleSpecList &rhs) {
  if (this != &rhs)
    *m_opaque_up = *rhs.m_opaque_up;
  return *this;
}

SBModuleSpecList::~SBModuleSpecList() {}

SBModuleSpecList SBModuleSpecList::GetModuleSpecifications(const char *path) {
  SBModuleSpecList specs;
  FileSpec file_spec(path);
  FileSystem::Instance().Resolve(file_spec);
  Host::ResolveExecutableInBundle(file_spec);
  ObjectFile::GetModuleSpecifications(file_spec, 0, 0, *specs.m_opaque_up);
  return specs;
}

void SBModuleSpecList::Append(const SBModuleSpec &spec) {
  m_opaque_up->Append(*spec.m_opaque_up);
}

void SBModuleSpecList::Append(const SBModuleSpecList &spec_list) {
  m_opaque_up->Append(*spec_list.m_opaque_up);
}

size_t SBModuleSpecList::GetSize() { return m_opaque_up->GetSize(); }

SBModuleSpec SBModuleSpecList::GetSpecAtIndex(size_t i) {
  SBModuleSpec sb_module_spec;
  m_opaque_up->GetModuleSpecAtIndex(i, *sb_module_spec.m_opaque_up);
  return sb_module_spec;
}

SBModuleSpec
SBModuleSpecList::FindFirstMatchingSpec(const SBModuleSpec &match_spec) {
  SBModuleSpec sb_module_spec;
  m_opaque_up->FindMatchingModuleSpec(*match_spec.m_opaque_up,
                                      *sb_module_spec.m_opaque_up);
  return sb_module_spec;
}

SBModuleSpecList
SBModuleSpecList::FindMatchingSpecs(const SBModuleSpec &match_spec) {
  SBModuleSpecList specs;
  m_opaque_up->FindMatchingModuleSpecs(*match_spec.m_opaque_up,
                                       *specs.m_opaque_up);
  return specs;
}

bool SBModuleSpecList::GetDescription(lldb::SBStream &description) {
  m_opaque_up->Dump(description.ref());
  return true;
}
