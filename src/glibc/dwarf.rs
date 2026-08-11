// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Minimal DWARF reader for the glibc malloc structures consumed by this tool.
//!
//! The extracted layout is applied to the existing
//! `DetectedLayout`; if any required type is unavailable, ambiguous, or fails
//! validation, the caller keeps the complete built-in layout.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, LittleEndian, Operation, Reader,
    SectionId, Unit, UnitHeader, UnitOffset, UnitType,
};
use goblin::elf::section_header::SHF_COMPRESSED;

use crate::elf::Elf;

type ReaderSlice<'a> = EndianSlice<'a, LittleEndian>;
type DwarfUnit<'a> = Unit<ReaderSlice<'a>>;
type DwarfUnitHeader<'a> = UnitHeader<ReaderSlice<'a>>;
type DwarfEntry<'abbrev, 'unit, 'input> =
    DebuggingInformationEntry<'abbrev, 'unit, ReaderSlice<'input>>;

// Debuginfo is external input, so every walk and allocation has a fixed bound.
const MAX_DIES: u64 = 2_000_000;
const MAX_UNITS: usize = 200_000;
const MAX_TARGET_CANDIDATES: usize = 4_096;
const MAX_SECTION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_DWARF_BYTES: u64 = 256 * 1024 * 1024;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_REFERENCE_DEPTH: u32 = 64;
const MAX_STRUCT_SIZE: u64 = 1024 * 1024;
const MAX_FIELD_OFFSET: u64 = 1024 * 1024;
const MAX_ARRAY_BYTES: u64 = 1024 * 1024;
const MAX_FASTBINS: u64 = 256;
const MAX_TCACHE_BINS: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DwarfLayout {
    pub(super) malloc_state_size: u32,
    pub(super) fastbin_array_offset: u32,
    pub(super) fastbin_count: u32,
    pub(super) malloc_state_top_offset: u32,
    pub(super) malloc_state_next_offset: u32,

    pub(super) mp_arena_max_offset: Option<u32>,
    pub(super) mp_sbrk_base_offset: u32,
    pub(super) mp_tcache_bins_offset: Option<u32>,

    pub(super) heap_info_size: u32,
    pub(super) heap_info_ar_ptr_offset: u32,
    pub(super) heap_info_prev_offset: u32,
    pub(super) heap_info_size_offset: u32,
    pub(super) heap_info_mprotect_size_offset: u32,

    pub(super) tcache_entries_offset: Option<u32>,
    pub(super) tcache_max_bins: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(super) enum DwarfLayoutError {
    #[error("DWARF debug_info is unavailable")]
    Unavailable,
    #[error("unsupported DWARF feature: {0}")]
    Unsupported(&'static str),
    #[error("DWARF resource limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid DWARF malloc layout: {0}")]
    Invalid(String),
    #[error("failed to parse DWARF: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    MallocState,
    MallocPar,
    HeapInfo,
    Tcache,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Target::MallocState => "malloc_state",
            Target::MallocPar => "malloc_par",
            Target::HeapInfo => "heap_info",
            Target::Tcache => "tcache_perthread_struct",
        }
    }

    fn wanted_members(self) -> &'static [&'static str] {
        match self {
            Target::MallocState => &["fastbinsY", "top", "next"],
            Target::MallocPar => &["arena_max", "sbrk_base", "tcache_bins"],
            Target::HeapInfo => &["ar_ptr", "prev", "size", "mprotect_size"],
            Target::Tcache => &["counts", "entries"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TypeKind {
    Pointer,
    Unsigned,
    Signed,
    Array,
    Structure,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TypeInfo {
    kind: TypeKind,
    byte_size: Option<u64>,
    element_kind: Option<TypeKind>,
    element_size: Option<u64>,
    element_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Member {
    name: String,
    offset: u64,
    ty: TypeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Structure {
    byte_size: u64,
    members: Vec<Member>,
}

#[derive(Default)]
struct TypeIndex {
    candidates: BTreeMap<Target, Vec<Structure>>,
    errors: BTreeMap<Target, DwarfLayoutError>,
}

/// Extract the complete set of offsets used by heap analysis.
pub(super) fn extract_layout(
    elf: &Elf<'_>,
    require_tcache: bool,
) -> Result<DwarfLayout, DwarfLayoutError> {
    let sections = load_sections(elf)?;
    if sections.get(".debug_info").unwrap_or_default().is_empty() {
        return Err(DwarfLayoutError::Unavailable);
    }
    if sections
        .get(".debug_types")
        .is_some_and(|section| !section.is_empty())
    {
        return Err(DwarfLayoutError::Unsupported("DWARF4 type units"));
    }

    let dwarf = Dwarf::load(|id: SectionId| {
        Ok::<_, gimli::Error>(EndianSlice::new(
            sections.get(id.name()).unwrap_or_default(),
            LittleEndian,
        ))
    })
    .map_err(parse_error)?;

    // Absolute DIE references contain a .debug_info offset. Keep the ordered
    // unit headers so their owner can be found without rescanning every unit.
    let mut headers = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(parse_error)? {
        if headers.len() >= MAX_UNITS {
            return Err(DwarfLayoutError::Limit("unit count"));
        }
        match header.type_() {
            UnitType::Compilation | UnitType::Partial => {}
            UnitType::Type { .. } | UnitType::SplitType { .. } => {
                return Err(DwarfLayoutError::Unsupported("type unit"));
            }
            UnitType::Skeleton(_) | UnitType::SplitCompilation(_) => {
                return Err(DwarfLayoutError::Unsupported("split DWARF"));
            }
        }
        headers.push(header);
    }

    let mut index = TypeIndex::default();
    let mut dies = 0u64;
    let mut candidate_count = 0usize;
    for header in &headers {
        let unit = dwarf.unit(*header).map_err(parse_error)?;
        if unit.dwo_id.is_some() || unit.dwo_name().map_err(parse_error)?.is_some() {
            return Err(DwarfLayoutError::Unsupported("split DWARF"));
        }
        scan_unit(
            &dwarf,
            &headers,
            &unit,
            &mut dies,
            &mut candidate_count,
            &mut index,
        )?;
    }

    let word_size = if elf.is_64bit() { 8 } else { 4 };
    assemble_layout(&index, word_size, require_tcache)
}

fn scan_unit<'input>(
    dwarf: &Dwarf<ReaderSlice<'input>>,
    headers: &[DwarfUnitHeader<'input>],
    unit: &DwarfUnit<'input>,
    dies: &mut u64,
    candidate_count: &mut usize,
    index: &mut TypeIndex,
) -> Result<(), DwarfLayoutError> {
    let mut found = Vec::new();
    let mut entries = unit.entries();
    while let Some((_, entry)) = entries.next_dfs().map_err(parse_error)? {
        *dies = dies
            .checked_add(1)
            .ok_or(DwarfLayoutError::Limit("DIE count"))?;
        if *dies > MAX_DIES {
            return Err(DwarfLayoutError::Limit("DIE count"));
        }
        if !matches!(
            entry.tag(),
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_typedef
        ) {
            continue;
        }
        let Some(name) = entry_name(dwarf, unit, entry)? else {
            continue;
        };
        if let Some(target) = target_name(&name) {
            *candidate_count = candidate_count
                .checked_add(1)
                .ok_or(DwarfLayoutError::Limit("target type candidates"))?;
            if *candidate_count > MAX_TARGET_CANDIDATES {
                return Err(DwarfLayoutError::Limit("target type candidates"));
            }
            found.push((target, entry.offset()));
        }
    }

    let mut seen = BTreeSet::new();
    for (target, offset) in found {
        let result = (|| {
            let mut visited = BTreeSet::new();
            let (owner, structure_offset) =
                resolve_structure(dwarf, headers, unit, offset, 0, &mut visited)?;
            let id = global_die_id(&owner, structure_offset)?;
            if !seen.insert((target, id)) {
                return Ok(None);
            }
            parse_structure(dwarf, headers, &owner, structure_offset, target).map(Some)
        })();
        match result {
            Ok(Some(structure)) => index.candidates.entry(target).or_default().push(structure),
            Ok(None) => {}
            Err(error @ DwarfLayoutError::Limit(_)) => return Err(error),
            Err(error) => {
                index.errors.entry(target).or_insert(error);
            }
        }
    }
    Ok(())
}

fn resolve_structure<'input>(
    dwarf: &Dwarf<ReaderSlice<'input>>,
    headers: &[DwarfUnitHeader<'input>],
    unit: &DwarfUnit<'input>,
    offset: UnitOffset<usize>,
    depth: u32,
    visited: &mut BTreeSet<(u64, u64)>,
) -> Result<(DwarfUnit<'input>, UnitOffset<usize>), DwarfLayoutError> {
    if depth >= MAX_REFERENCE_DEPTH {
        return Err(DwarfLayoutError::Limit("type reference depth"));
    }
    if !visited.insert(global_die_id(unit, offset)?) {
        return Err(DwarfLayoutError::Invalid(
            "type reference cycle".to_string(),
        ));
    }
    let entry = unit.entry(offset).map_err(parse_error)?;
    if matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type
    ) {
        return Ok((reload_unit(dwarf, unit)?, offset));
    }
    if matches!(
        entry.tag(),
        gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type
    ) {
        let value = entry
            .attr_value(gimli::DW_AT_type)
            .map_err(parse_error)?
            .ok_or_else(|| DwarfLayoutError::Invalid("type reference is missing".to_string()))?;
        let (next_unit, next) = attribute_die_ref(dwarf, headers, unit, value)?;
        return resolve_structure(dwarf, headers, &next_unit, next, depth + 1, visited);
    }
    Err(DwarfLayoutError::Invalid(
        "target does not resolve to a structure".to_string(),
    ))
}

fn parse_structure(
    dwarf: &Dwarf<ReaderSlice<'_>>,
    headers: &[DwarfUnitHeader<'_>],
    unit: &DwarfUnit<'_>,
    offset: UnitOffset<usize>,
    target: Target,
) -> Result<Structure, DwarfLayoutError> {
    let entry = unit.entry(offset).map_err(parse_error)?;
    let declaration = entry
        .attr_value(gimli::DW_AT_declaration)
        .map_err(parse_error)?
        .and_then(|value| match value {
            AttributeValue::Flag(flag) => Some(flag),
            other => other.udata_value().map(|value| value != 0),
        })
        .unwrap_or(false);
    if declaration {
        return Err(DwarfLayoutError::Invalid(
            "target is only a declaration".to_string(),
        ));
    }
    let byte_size = entry
        .attr_value(gimli::DW_AT_byte_size)
        .map_err(parse_error)?
        .and_then(|value| value.udata_value())
        .ok_or_else(|| DwarfLayoutError::Invalid("structure has no byte size".to_string()))?;
    validate_struct_size(byte_size, unit.encoding().address_size)?;

    let wanted = target.wanted_members();
    let mut members = Vec::new();
    let mut tree = unit.entries_tree(Some(offset)).map_err(parse_error)?;
    let root = tree.root().map_err(parse_error)?;
    let mut children = root.children();
    while let Some(child) = children.next().map_err(parse_error)? {
        let member = child.entry();
        if member.tag() != gimli::DW_TAG_member {
            continue;
        }
        let Some(name) = entry_name(dwarf, unit, member)? else {
            continue;
        };
        if !wanted.contains(&name.as_str()) {
            continue;
        }
        let offset = member_location(member, unit)?;
        let type_value = member
            .attr_value(gimli::DW_AT_type)
            .map_err(parse_error)?
            .ok_or_else(|| DwarfLayoutError::Invalid(format!("{name} has no type")))?;
        let (type_unit, type_offset) = attribute_die_ref(dwarf, headers, unit, type_value)?;
        let mut visited = BTreeSet::new();
        let ty = resolve_type(dwarf, headers, &type_unit, type_offset, 0, &mut visited)?;
        members.push(Member { name, offset, ty });
    }
    members.sort();
    members.dedup();
    Ok(Structure { byte_size, members })
}

fn resolve_type(
    dwarf: &Dwarf<ReaderSlice<'_>>,
    headers: &[DwarfUnitHeader<'_>],
    unit: &DwarfUnit<'_>,
    offset: UnitOffset<usize>,
    depth: u32,
    visited: &mut BTreeSet<(u64, u64)>,
) -> Result<TypeInfo, DwarfLayoutError> {
    if depth >= MAX_REFERENCE_DEPTH {
        return Err(DwarfLayoutError::Limit("type reference depth"));
    }
    if !visited.insert(global_die_id(unit, offset)?) {
        return Err(DwarfLayoutError::Invalid(
            "type reference cycle".to_string(),
        ));
    }
    let entry = unit.entry(offset).map_err(parse_error)?;
    let byte_size = entry
        .attr_value(gimli::DW_AT_byte_size)
        .map_err(parse_error)?
        .and_then(|value| value.udata_value());

    match entry.tag() {
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_atomic_type => {
            let value = entry
                .attr_value(gimli::DW_AT_type)
                .map_err(parse_error)?
                .ok_or_else(|| {
                    DwarfLayoutError::Invalid("type reference is missing".to_string())
                })?;
            let (next_unit, next) = attribute_die_ref(dwarf, headers, unit, value)?;
            resolve_type(dwarf, headers, &next_unit, next, depth + 1, visited)
        }
        gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type => Ok(TypeInfo {
            kind: TypeKind::Pointer,
            byte_size: byte_size.or(Some(u64::from(unit.encoding().address_size))),
            element_kind: None,
            element_size: None,
            element_count: None,
        }),
        gimli::DW_TAG_array_type => {
            let value = entry
                .attr_value(gimli::DW_AT_type)
                .map_err(parse_error)?
                .ok_or_else(|| {
                    DwarfLayoutError::Invalid("array element type is missing".to_string())
                })?;
            let (element_unit, element_offset) = attribute_die_ref(dwarf, headers, unit, value)?;
            let element = resolve_type(
                dwarf,
                headers,
                &element_unit,
                element_offset,
                depth + 1,
                visited,
            )?;
            let dimensions = array_dimensions(unit, offset)?;
            let element_count = dimensions.as_ref().and_then(|dimensions| {
                dimensions
                    .iter()
                    .try_fold(1u64, |total, count| total.checked_mul(*count))
            });
            let computed_size = element
                .byte_size
                .zip(element_count)
                .and_then(|(size, count)| size.checked_mul(count));
            Ok(TypeInfo {
                kind: TypeKind::Array,
                byte_size: byte_size.or(computed_size),
                element_kind: Some(element.kind),
                element_size: element.byte_size,
                element_count,
            })
        }
        gimli::DW_TAG_base_type | gimli::DW_TAG_enumeration_type => {
            let encoding = entry
                .attr_value(gimli::DW_AT_encoding)
                .map_err(parse_error)?
                .and_then(|value| match value {
                    AttributeValue::Encoding(encoding) => Some(encoding),
                    _ => None,
                });
            let kind = if matches!(
                encoding,
                Some(gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char | gimli::DW_ATE_boolean)
            ) {
                TypeKind::Unsigned
            } else {
                TypeKind::Signed
            };
            Ok(TypeInfo {
                kind,
                byte_size,
                element_kind: None,
                element_size: None,
                element_count: None,
            })
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => Ok(TypeInfo {
            kind: TypeKind::Structure,
            byte_size,
            element_kind: None,
            element_size: None,
            element_count: None,
        }),
        _ => Ok(TypeInfo {
            kind: TypeKind::Other,
            byte_size,
            element_kind: None,
            element_size: None,
            element_count: None,
        }),
    }
}

fn array_dimensions(
    unit: &DwarfUnit<'_>,
    offset: UnitOffset<usize>,
) -> Result<Option<Vec<u64>>, DwarfLayoutError> {
    let mut tree = unit.entries_tree(Some(offset)).map_err(parse_error)?;
    let root = tree.root().map_err(parse_error)?;
    let mut children = root.children();
    let mut dimensions = Vec::new();
    while let Some(child) = children.next().map_err(parse_error)? {
        let subrange = child.entry();
        if subrange.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        let count = subrange
            .attr_value(gimli::DW_AT_count)
            .map_err(parse_error)?
            .and_then(|value| value.udata_value());
        let lower = attr_i128(subrange, gimli::DW_AT_lower_bound)?.unwrap_or(0);
        let upper = attr_i128(subrange, gimli::DW_AT_upper_bound)?;
        let bounds_count = upper
            .map(|upper| {
                upper
                    .checked_sub(lower)
                    .and_then(|value| value.checked_add(1))
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or_else(|| DwarfLayoutError::Invalid("invalid array bounds".to_string()))
            })
            .transpose()?;
        let dimension = match (count, bounds_count) {
            (Some(left), Some(right)) if left != right => {
                return Err(DwarfLayoutError::Invalid(
                    "array count conflicts with bounds".to_string(),
                ));
            }
            (Some(count), _) | (None, Some(count)) => count,
            (None, None) => return Ok(None),
        };
        dimensions.push(dimension);
    }
    if dimensions.is_empty() {
        Ok(None)
    } else {
        Ok(Some(dimensions))
    }
}

fn attr_i128(
    entry: &DwarfEntry<'_, '_, '_>,
    name: gimli::DwAt,
) -> Result<Option<i128>, DwarfLayoutError> {
    Ok(entry
        .attr_value(name)
        .map_err(parse_error)?
        .and_then(|value| match value {
            AttributeValue::Sdata(value) => Some(i128::from(value)),
            other => other.udata_value().map(i128::from),
        }))
}

fn member_location(
    entry: &DwarfEntry<'_, '_, '_>,
    unit: &DwarfUnit<'_>,
) -> Result<u64, DwarfLayoutError> {
    let value = entry
        .attr_value(gimli::DW_AT_data_member_location)
        .map_err(parse_error)?
        .ok_or_else(|| DwarfLayoutError::Invalid("member has no location".to_string()))?;
    if let Some(value) = value.udata_value() {
        return Ok(value);
    }
    let AttributeValue::Exprloc(expression) = value else {
        return Err(DwarfLayoutError::Unsupported(
            "non-constant member location",
        ));
    };
    let mut operations = expression.operations(unit.encoding());
    match (
        operations.next().map_err(parse_error)?,
        operations.next().map_err(parse_error)?,
    ) {
        (Some(Operation::PlusConstant { value }), None) => Ok(value),
        _ => Err(DwarfLayoutError::Unsupported("member location expression")),
    }
}

fn entry_name(
    dwarf: &Dwarf<ReaderSlice<'_>>,
    unit: &DwarfUnit<'_>,
    entry: &DwarfEntry<'_, '_, '_>,
) -> Result<Option<String>, DwarfLayoutError> {
    let Some(value) = entry.attr_value(gimli::DW_AT_name).map_err(parse_error)? else {
        return Ok(None);
    };
    if matches!(value, AttributeValue::DebugStrRefSup(_)) {
        return Err(DwarfLayoutError::Unsupported("supplementary DWARF string"));
    }
    let value = dwarf.attr_string(unit, value).map_err(parse_error)?;
    let bytes = value.to_slice().map_err(parse_error)?;
    if bytes.len() > MAX_STRING_BYTES {
        return Err(DwarfLayoutError::Limit("DWARF string length"));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| DwarfLayoutError::Invalid("non-UTF-8 DWARF name".to_string()))?;
    Ok(Some(value.to_string()))
}

fn target_name(name: &str) -> Option<Target> {
    let name = name
        .trim()
        .strip_prefix("struct ")
        .or_else(|| name.trim().strip_prefix("class "))
        .unwrap_or_else(|| name.trim());
    match name {
        "malloc_state" | "_malloc_state" => Some(Target::MallocState),
        "malloc_par" => Some(Target::MallocPar),
        "heap_info" | "_heap_info" => Some(Target::HeapInfo),
        "tcache_perthread_struct" => Some(Target::Tcache),
        _ => None,
    }
}

fn attribute_die_ref<'input>(
    dwarf: &Dwarf<ReaderSlice<'input>>,
    headers: &[DwarfUnitHeader<'input>],
    unit: &DwarfUnit<'input>,
    value: AttributeValue<ReaderSlice<'input>>,
) -> Result<(DwarfUnit<'input>, UnitOffset<usize>), DwarfLayoutError> {
    match value {
        AttributeValue::UnitRef(offset) => Ok((reload_unit(dwarf, unit)?, offset)),
        AttributeValue::DebugInfoRef(offset) => load_unit_at(dwarf, headers, offset),
        AttributeValue::DebugInfoRefSup(_) => Err(DwarfLayoutError::Unsupported(
            "supplementary type reference",
        )),
        AttributeValue::DebugTypesRef(_) => {
            Err(DwarfLayoutError::Unsupported("type signature reference"))
        }
        _ => Err(DwarfLayoutError::Invalid(
            "invalid type reference".to_string(),
        )),
    }
}

fn reload_unit<'input>(
    dwarf: &Dwarf<ReaderSlice<'input>>,
    unit: &DwarfUnit<'input>,
) -> Result<DwarfUnit<'input>, DwarfLayoutError> {
    let offset = unit
        .header
        .offset()
        .as_debug_info_offset()
        .ok_or(DwarfLayoutError::Unsupported("non-debug_info unit"))?;
    let header = dwarf
        .debug_info
        .header_from_offset(offset)
        .map_err(parse_error)?;
    dwarf.unit(header).map_err(parse_error)
}

fn load_unit_at<'input>(
    dwarf: &Dwarf<ReaderSlice<'input>>,
    headers: &[DwarfUnitHeader<'input>],
    absolute: gimli::DebugInfoOffset<usize>,
) -> Result<(DwarfUnit<'input>, UnitOffset<usize>), DwarfLayoutError> {
    // Unit headers are stored in .debug_info order; the preceding header is
    // the only unit that can contain this absolute offset.
    let next = headers.partition_point(|header| {
        header
            .offset()
            .as_debug_info_offset()
            .is_some_and(|offset| offset.0 <= absolute.0)
    });
    if let Some(header) = next.checked_sub(1).and_then(|index| headers.get(index)) {
        if let Some(offset) = absolute.to_unit_offset(header) {
            let unit = dwarf.unit(*header).map_err(parse_error)?;
            return Ok((unit, offset));
        }
    }
    Err(DwarfLayoutError::Invalid(
        "cross-unit reference is outside debug_info".to_string(),
    ))
}

fn global_die_id(
    unit: &DwarfUnit<'_>,
    offset: UnitOffset<usize>,
) -> Result<(u64, u64), DwarfLayoutError> {
    let unit_offset = unit
        .header
        .offset()
        .as_debug_info_offset()
        .ok_or(DwarfLayoutError::Unsupported("non-debug_info unit"))?
        .0;
    Ok((
        u64::try_from(unit_offset)
            .map_err(|_| DwarfLayoutError::Invalid("unit offset overflow".to_string()))?,
        u64::try_from(offset.0)
            .map_err(|_| DwarfLayoutError::Invalid("DIE offset overflow".to_string()))?,
    ))
}

fn assemble_layout(
    index: &TypeIndex,
    word_size: u64,
    require_tcache: bool,
) -> Result<DwarfLayout, DwarfLayoutError> {
    if !matches!(word_size, 4 | 8) {
        return Err(DwarfLayoutError::Invalid(
            "unsupported target word size".to_string(),
        ));
    }
    let malloc_state = select(index, Target::MallocState, |structure| {
        validate_malloc_state(structure, word_size)
    })?;
    let malloc_par = select(index, Target::MallocPar, |structure| {
        validate_malloc_par(structure, word_size)
    })?;
    let heap_info = select(index, Target::HeapInfo, |structure| {
        validate_heap_info(structure, word_size)
    })?;
    let tcache = if require_tcache {
        Some(select(index, Target::Tcache, |structure| {
            validate_tcache(structure, word_size)
        })?)
    } else {
        None
    };

    Ok(DwarfLayout {
        malloc_state_size: checked_u32(malloc_state.size, "malloc_state size")?,
        fastbin_array_offset: checked_u32(malloc_state.fastbins, "fastbinsY offset")?,
        fastbin_count: checked_u32(malloc_state.fastbin_count, "fastbin count")?,
        malloc_state_top_offset: checked_u32(malloc_state.top, "top offset")?,
        malloc_state_next_offset: checked_u32(malloc_state.next, "next offset")?,
        mp_arena_max_offset: malloc_par
            .arena_max
            .map(|value| checked_u32(value, "arena_max offset"))
            .transpose()?,
        mp_sbrk_base_offset: checked_u32(malloc_par.sbrk_base, "sbrk_base offset")?,
        mp_tcache_bins_offset: malloc_par
            .tcache_bins
            .map(|value| checked_u32(value, "tcache_bins offset"))
            .transpose()?,
        heap_info_size: checked_u32(heap_info.size, "heap_info size")?,
        heap_info_ar_ptr_offset: checked_u32(heap_info.ar_ptr, "ar_ptr offset")?,
        heap_info_prev_offset: checked_u32(heap_info.prev, "prev offset")?,
        heap_info_size_offset: checked_u32(heap_info.current_size, "size offset")?,
        heap_info_mprotect_size_offset: checked_u32(
            heap_info.mprotect_size,
            "mprotect_size offset",
        )?,
        tcache_entries_offset: tcache
            .as_ref()
            .map(|value| checked_u32(value.entries, "tcache entries offset"))
            .transpose()?,
        tcache_max_bins: tcache
            .as_ref()
            .map(|value| checked_u32(value.bins, "tcache bin count"))
            .transpose()?,
    })
}

fn select<T: Clone + PartialEq, F>(
    index: &TypeIndex,
    target: Target,
    validate: F,
) -> Result<T, DwarfLayoutError>
where
    F: Fn(&Structure) -> Result<T, DwarfLayoutError>,
{
    let Some(candidates) = index.candidates.get(&target) else {
        return Err(index.errors.get(&target).cloned().unwrap_or_else(|| {
            DwarfLayoutError::Invalid(format!("missing DWARF type {}", target.name()))
        }));
    };
    // A type may be repeated in several compilation units. Equal layouts are
    // one candidate; conflicting valid layouts are unsafe to choose between.
    let mut valid = Vec::new();
    let mut first_error = None;
    for candidate in candidates {
        match validate(candidate) {
            Ok(value) if !valid.contains(&value) => valid.push(value),
            Ok(_) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match valid.len() {
        1 => Ok(valid.remove(0)),
        0 => Err(first_error.unwrap_or_else(|| {
            DwarfLayoutError::Invalid(format!("no usable {} definition", target.name()))
        })),
        _ => Err(DwarfLayoutError::Invalid(format!(
            "ambiguous {} definitions",
            target.name()
        ))),
    }
}

#[derive(Clone, PartialEq)]
struct MallocStateLayout {
    size: u64,
    fastbins: u64,
    fastbin_count: u64,
    top: u64,
    next: u64,
}

fn validate_malloc_state(
    structure: &Structure,
    word: u64,
) -> Result<MallocStateLayout, DwarfLayoutError> {
    let fastbins = required_member(structure, "fastbinsY")?;
    let (_, fastbin_count) = pointer_array(fastbins, structure.byte_size, word)?;
    if fastbin_count == 0 || fastbin_count > MAX_FASTBINS {
        return invalid("fastbinsY element count is out of range");
    }
    let top = required_member(structure, "top")?;
    pointer(top, structure.byte_size, word)?;
    let next = required_member(structure, "next")?;
    pointer(next, structure.byte_size, word)?;
    no_overlap(&[fastbins, top, next])?;
    Ok(MallocStateLayout {
        size: structure.byte_size,
        fastbins: fastbins.offset,
        fastbin_count,
        top: top.offset,
        next: next.offset,
    })
}

#[derive(Clone, PartialEq)]
struct MallocParLayout {
    arena_max: Option<u64>,
    sbrk_base: u64,
    tcache_bins: Option<u64>,
}

fn validate_malloc_par(
    structure: &Structure,
    word: u64,
) -> Result<MallocParLayout, DwarfLayoutError> {
    let sbrk_base = required_member(structure, "sbrk_base")?;
    pointer(sbrk_base, structure.byte_size, word)?;
    let arena_max = optional_word_member(structure, "arena_max", word)?;
    let tcache_bins = optional_word_member(structure, "tcache_bins", word)?;
    Ok(MallocParLayout {
        arena_max,
        sbrk_base: sbrk_base.offset,
        tcache_bins,
    })
}

#[derive(Clone, PartialEq)]
struct HeapInfoLayout {
    size: u64,
    ar_ptr: u64,
    prev: u64,
    current_size: u64,
    mprotect_size: u64,
}

fn validate_heap_info(
    structure: &Structure,
    word: u64,
) -> Result<HeapInfoLayout, DwarfLayoutError> {
    let ar_ptr = required_member(structure, "ar_ptr")?;
    pointer(ar_ptr, structure.byte_size, word)?;
    let prev = required_member(structure, "prev")?;
    pointer(prev, structure.byte_size, word)?;
    let size = required_member(structure, "size")?;
    unsigned_word(size, structure.byte_size, word)?;
    let mprotect_size = required_member(structure, "mprotect_size")?;
    unsigned_word(mprotect_size, structure.byte_size, word)?;
    no_overlap(&[ar_ptr, prev, size, mprotect_size])?;
    Ok(HeapInfoLayout {
        size: structure.byte_size,
        ar_ptr: ar_ptr.offset,
        prev: prev.offset,
        current_size: size.offset,
        mprotect_size: mprotect_size.offset,
    })
}

#[derive(Clone, PartialEq)]
struct TcacheLayout {
    entries: u64,
    bins: u64,
}

fn validate_tcache(structure: &Structure, word: u64) -> Result<TcacheLayout, DwarfLayoutError> {
    let counts = required_member(structure, "counts")?;
    let (count_width, count_bins) = integer_array(counts, structure.byte_size)?;
    // glibc 2.28 used signed char counters; newer releases use wider unsigned
    // counters, so signedness alone does not identify an invalid layout.
    if !matches!(count_width, 1 | 2 | 4 | 8) {
        return invalid("tcache counts uses an unsupported integer width");
    }
    let entries = required_member(structure, "entries")?;
    let (_, entry_bins) = pointer_array(entries, structure.byte_size, word)?;
    if count_bins == 0 || count_bins != entry_bins || entry_bins > MAX_TCACHE_BINS {
        return invalid("tcache counts and entries dimensions differ or are out of range");
    }
    no_overlap(&[counts, entries])?;
    Ok(TcacheLayout {
        entries: entries.offset,
        bins: entry_bins,
    })
}

fn required_member<'a>(
    structure: &'a Structure,
    name: &str,
) -> Result<&'a Member, DwarfLayoutError> {
    let mut matches = structure
        .members
        .iter()
        .filter(|member| member.name == name);
    let Some(member) = matches.next() else {
        return invalid(format!("missing required member {name}"));
    };
    if matches.next().is_some() {
        return invalid(format!("member {name} is ambiguous"));
    }
    Ok(member)
}

fn optional_word_member(
    structure: &Structure,
    name: &str,
    word: u64,
) -> Result<Option<u64>, DwarfLayoutError> {
    let matches: Vec<_> = structure
        .members
        .iter()
        .filter(|member| member.name == name)
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [member] => {
            unsigned_word(member, structure.byte_size, word)?;
            Ok(Some(member.offset))
        }
        _ => invalid(format!("member {name} is ambiguous")),
    }
}

fn pointer(member: &Member, struct_size: u64, word: u64) -> Result<(), DwarfLayoutError> {
    field_range(member, struct_size)?;
    if member.ty.kind != TypeKind::Pointer
        || member.ty.byte_size != Some(word)
        || member.offset % word != 0
    {
        return invalid(format!("{} is not a word-aligned pointer", member.name));
    }
    Ok(())
}

fn unsigned_word(member: &Member, struct_size: u64, word: u64) -> Result<(), DwarfLayoutError> {
    field_range(member, struct_size)?;
    if member.ty.kind != TypeKind::Unsigned
        || member.ty.byte_size != Some(word)
        || member.offset % word != 0
    {
        return invalid(format!(
            "{} is not a word-aligned unsigned integer",
            member.name
        ));
    }
    Ok(())
}

fn pointer_array(
    member: &Member,
    struct_size: u64,
    word: u64,
) -> Result<(u64, u64), DwarfLayoutError> {
    array(member, struct_size, TypeKind::Pointer, Some(word))
}

fn integer_array(member: &Member, struct_size: u64) -> Result<(u64, u64), DwarfLayoutError> {
    if !matches!(
        member.ty.element_kind,
        Some(TypeKind::Unsigned | TypeKind::Signed)
    ) {
        return invalid(format!("{} is not an integer array", member.name));
    }
    array(
        member,
        struct_size,
        member.ty.element_kind.expect("checked above"),
        None,
    )
}

fn array(
    member: &Member,
    struct_size: u64,
    kind: TypeKind,
    expected_width: Option<u64>,
) -> Result<(u64, u64), DwarfLayoutError> {
    field_range(member, struct_size)?;
    let ty = &member.ty;
    if ty.kind != TypeKind::Array || ty.element_kind != Some(kind) {
        return invalid(format!("{} has the wrong array element type", member.name));
    }
    let width = ty
        .element_size
        .ok_or_else(|| DwarfLayoutError::Invalid(format!("{} has no element size", member.name)))?;
    let count = ty.element_count.ok_or_else(|| {
        DwarfLayoutError::Invalid(format!("{} has no element count", member.name))
    })?;
    if width == 0 || count == 0 || expected_width.is_some_and(|expected| expected != width) {
        return invalid(format!("{} has an invalid array shape", member.name));
    }
    let bytes = width
        .checked_mul(count)
        .ok_or(DwarfLayoutError::Limit("array byte size"))?;
    if bytes > MAX_ARRAY_BYTES || ty.byte_size != Some(bytes) {
        return invalid(format!("{} array byte size is inconsistent", member.name));
    }
    Ok((width, count))
}

fn field_range(member: &Member, struct_size: u64) -> Result<(), DwarfLayoutError> {
    let size = member
        .ty
        .byte_size
        .ok_or_else(|| DwarfLayoutError::Invalid(format!("{} has no byte size", member.name)))?;
    let end = member
        .offset
        .checked_add(size)
        .ok_or(DwarfLayoutError::Limit("field range"))?;
    if size == 0 || member.offset > MAX_FIELD_OFFSET || end > struct_size {
        return invalid(format!("{} is outside its structure", member.name));
    }
    Ok(())
}

fn no_overlap(members: &[&Member]) -> Result<(), DwarfLayoutError> {
    for (index, left) in members.iter().enumerate() {
        let left_size = left.ty.byte_size.unwrap_or(0);
        let left_end = left.offset.saturating_add(left_size);
        for right in &members[index + 1..] {
            let right_size = right.ty.byte_size.unwrap_or(0);
            let right_end = right.offset.saturating_add(right_size);
            if left.offset < right_end && right.offset < left_end {
                return invalid(format!("{} and {} overlap", left.name, right.name));
            }
        }
    }
    Ok(())
}

fn validate_struct_size(size: u64, word: u8) -> Result<(), DwarfLayoutError> {
    let word = u64::from(word);
    if size == 0 || size > MAX_STRUCT_SIZE || !matches!(word, 4 | 8) || size % word != 0 {
        return invalid("structure size is zero, unaligned, or over the limit");
    }
    Ok(())
}

fn checked_u32(value: u64, field: &str) -> Result<u32, DwarfLayoutError> {
    u32::try_from(value).map_err(|_| DwarfLayoutError::Invalid(format!("{field} does not fit u32")))
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, DwarfLayoutError> {
    Err(DwarfLayoutError::Invalid(reason.into()))
}

struct SectionStore<'a> {
    sections: BTreeMap<String, Cow<'a, [u8]>>,
}

impl SectionStore<'_> {
    fn get(&self, name: &str) -> Option<&[u8]> {
        self.sections.get(name).map(Cow::as_ref)
    }
}

fn load_sections<'a>(elf: &'a Elf<'a>) -> Result<SectionStore<'a>, DwarfLayoutError> {
    let mut total = 0u64;
    let mut sections = BTreeMap::new();
    for section in &elf.inner().section_headers {
        let Some(name) = elf.inner().shdr_strtab.get_at(section.sh_name) else {
            continue;
        };
        let legacy_compressed = name.starts_with(".zdebug_");
        let canonical_name = if legacy_compressed {
            format!(".debug_{}", &name[8..])
        } else {
            name.to_string()
        };
        if !is_layout_section(&canonical_name) {
            continue;
        }
        let start = usize::try_from(section.sh_offset)
            .map_err(|_| DwarfLayoutError::Invalid("section offset overflow".to_string()))?;
        let size = usize::try_from(section.sh_size)
            .map_err(|_| DwarfLayoutError::Invalid("section size overflow".to_string()))?;
        let end = start
            .checked_add(size)
            .ok_or(DwarfLayoutError::Limit("section range"))?;
        let input = elf
            .bytes()
            .get(start..end)
            .ok_or_else(|| DwarfLayoutError::Invalid("section is outside ELF".to_string()))?;
        let elf_compressed = section.sh_flags & u64::from(SHF_COMPRESSED) != 0;
        let data = if legacy_compressed || elf_compressed {
            let (declared, payload) = compressed_payload(elf, input, legacy_compressed)?;
            // The expanded size is what determines memory use.
            reserve_section(&mut total, declared)?;
            Cow::Owned(decompress(payload, declared)?)
        } else {
            reserve_section(&mut total, section.sh_size)?;
            Cow::Borrowed(input)
        };
        if sections.insert(canonical_name, data).is_some() {
            return invalid("duplicate canonical DWARF section");
        }
    }
    Ok(SectionStore { sections })
}

/// Only load sections needed for type/name/member decoding. `gimli` consults
/// `.debug_line` while constructing a unit, but macro/range/location data must
/// not consume the layout reader's byte budget when this module never uses it.
fn is_layout_section(name: &str) -> bool {
    matches!(
        name,
        ".debug_abbrev"
            | ".debug_addr"
            | ".debug_info"
            | ".debug_line"
            | ".debug_line_str"
            | ".debug_str"
            | ".debug_str_offsets"
            | ".debug_types"
    )
}

fn reserve_section(total: &mut u64, size: u64) -> Result<(), DwarfLayoutError> {
    if size > MAX_SECTION_BYTES {
        return Err(DwarfLayoutError::Limit("DWARF section bytes"));
    }
    *total = total
        .checked_add(size)
        .ok_or(DwarfLayoutError::Limit("total DWARF bytes"))?;
    if *total > MAX_TOTAL_DWARF_BYTES {
        return Err(DwarfLayoutError::Limit("total DWARF bytes"));
    }
    Ok(())
}

fn compressed_payload<'a>(
    elf: &Elf<'_>,
    input: &'a [u8],
    legacy: bool,
) -> Result<(u64, &'a [u8]), DwarfLayoutError> {
    if legacy {
        if input.len() < 12 || &input[..4] != b"ZLIB" {
            return invalid("invalid legacy compressed section header");
        }
        let size = u64::from_be_bytes(
            input[4..12]
                .try_into()
                .map_err(|_| DwarfLayoutError::Invalid("compressed size header".to_string()))?,
        );
        return Ok((size, &input[12..]));
    }
    let (header_size, compression_type, size) =
        if elf.is_64bit() {
            if input.len() < 24 {
                return invalid("short ELF64 compression header");
            }
            (
                24,
                u32::from_le_bytes(input[0..4].try_into().map_err(|_| {
                    DwarfLayoutError::Invalid("compression type header".to_string())
                })?),
                u64::from_le_bytes(input[8..16].try_into().map_err(|_| {
                    DwarfLayoutError::Invalid("compressed size header".to_string())
                })?),
            )
        } else {
            if input.len() < 12 {
                return invalid("short ELF32 compression header");
            }
            (
                12,
                u32::from_le_bytes(input[0..4].try_into().map_err(|_| {
                    DwarfLayoutError::Invalid("compression type header".to_string())
                })?),
                u64::from(u32::from_le_bytes(input[4..8].try_into().map_err(
                    |_| DwarfLayoutError::Invalid("compressed size header".to_string()),
                )?)),
            )
        };
    if compression_type != 1 {
        return Err(DwarfLayoutError::Unsupported("non-zlib compression"));
    }
    Ok((size, &input[header_size..]))
}

fn decompress(payload: &[u8], declared: u64) -> Result<Vec<u8>, DwarfLayoutError> {
    let size = usize::try_from(declared).map_err(|_| DwarfLayoutError::Limit("section bytes"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| DwarfLayoutError::Limit("section allocation"))?;
    // Read one byte beyond the declared size so an incorrect header cannot
    // silently truncate the section.
    let mut decoder = flate2::read::ZlibDecoder::new(payload).take(
        declared
            .checked_add(1)
            .ok_or(DwarfLayoutError::Limit("section bytes"))?,
    );
    decoder
        .read_to_end(&mut output)
        .map_err(|error| DwarfLayoutError::Parse(format!("zlib: {error}")))?;
    if output.len() != size {
        return invalid("decompressed size differs from section header");
    }
    Ok(output)
}

fn parse_error(error: gimli::Error) -> DwarfLayoutError {
    DwarfLayoutError::Parse(format!("{error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[repr(C)]
    #[allow(non_snake_case, dead_code)]
    struct malloc_state {
        fastbinsY: [*mut u8; 10],
        top: *mut u8,
        next: *mut malloc_state,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct malloc_par {
        arena_max: usize,
        sbrk_base: *mut u8,
        tcache_bins: usize,
    }

    #[repr(C)]
    #[allow(non_camel_case_types, dead_code)]
    struct heap_info {
        ar_ptr: *mut malloc_state,
        prev: *mut heap_info,
        size: usize,
        mprotect_size: usize,
    }

    #[repr(C)]
    #[allow(non_camel_case_types, dead_code)]
    struct tcache_perthread_struct {
        counts: [u16; 64],
        entries: [*mut u8; 64],
    }

    #[test]
    fn extracts_the_required_layout_from_a_real_test_elf() {
        let values = (
            malloc_state {
                fastbinsY: [std::ptr::null_mut(); 10],
                top: std::ptr::null_mut(),
                next: std::ptr::null_mut(),
            },
            malloc_par {
                arena_max: 0,
                sbrk_base: std::ptr::null_mut(),
                tcache_bins: 64,
            },
            heap_info {
                ar_ptr: std::ptr::null_mut(),
                prev: std::ptr::null_mut(),
                size: 0,
                mprotect_size: 0,
            },
            tcache_perthread_struct {
                counts: [0; 64],
                entries: [std::ptr::null_mut(); 64],
            },
        );
        std::hint::black_box(values);

        let image = crate::elf::Image::load(&std::env::current_exe().unwrap()).unwrap();
        let elf = image.parse().unwrap();
        let layout = extract_layout(&elf, true).unwrap();
        assert_eq!(layout.fastbin_count, 10);
        assert_eq!(layout.tcache_max_bins, Some(64));
        assert_eq!(layout.tcache_entries_offset, Some(128));
    }

    #[test]
    fn target_names_are_exact() {
        assert_eq!(
            target_name("struct _malloc_state"),
            Some(Target::MallocState)
        );
        assert_eq!(target_name("not_malloc_state"), None);
        assert_eq!(target_name("malloc_state_extra"), None);
    }

    #[test]
    fn accepts_glibc_228_signed_byte_tcache_counts() {
        let index = valid_index(TypeKind::Signed, 1, 64);
        let layout = assemble_layout(&index, 8, true).unwrap();
        assert_eq!(layout.tcache_entries_offset, Some(64));
        assert_eq!(layout.tcache_max_bins, Some(64));
    }

    #[test]
    fn rejects_tcache_arrays_with_different_dimensions() {
        let index = valid_index(TypeKind::Unsigned, 2, 63);
        assert!(matches!(
            assemble_layout(&index, 8, true),
            Err(DwarfLayoutError::Invalid(reason))
                if reason.contains("dimensions differ")
        ));
    }

    #[test]
    fn rejects_fastbin_count_over_semantic_limit() {
        let mut index = valid_index(TypeKind::Unsigned, 2, 64);
        let state = &mut index.candidates.get_mut(&Target::MallocState).unwrap()[0];
        state.byte_size = 4096;
        let fastbins = state
            .members
            .iter_mut()
            .find(|member| member.name == "fastbinsY")
            .unwrap();
        fastbins.ty.byte_size = Some(257 * 8);
        fastbins.ty.element_count = Some(257);
        assert!(matches!(
            assemble_layout(&index, 8, true),
            Err(DwarfLayoutError::Invalid(reason))
                if reason.contains("fastbinsY element count")
        ));
    }

    #[test]
    fn rejects_two_distinct_valid_layouts_for_one_target() {
        let mut index = valid_index(TypeKind::Unsigned, 2, 64);
        let mut alternate = index.candidates[&Target::MallocState][0].clone();
        alternate.byte_size = 120;
        alternate
            .members
            .iter_mut()
            .find(|member| member.name == "top")
            .unwrap()
            .offset = 104;
        alternate
            .members
            .iter_mut()
            .find(|member| member.name == "next")
            .unwrap()
            .offset = 112;
        index
            .candidates
            .get_mut(&Target::MallocState)
            .unwrap()
            .push(alternate);
        assert!(matches!(
            assemble_layout(&index, 8, true),
            Err(DwarfLayoutError::Invalid(reason))
                if reason.contains("ambiguous malloc_state")
        ));
    }

    #[test]
    fn old_glibc_does_not_require_a_tcache_type() {
        let mut index = valid_index(TypeKind::Unsigned, 2, 64);
        index.candidates.remove(&Target::Tcache);
        let layout = assemble_layout(&index, 8, false).unwrap();
        assert_eq!(layout.tcache_entries_offset, None);
        assert_eq!(layout.tcache_max_bins, None);
    }

    #[test]
    fn decompresses_legacy_zlib_section() {
        let data = b"small DWARF section";
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut section = b"ZLIB".to_vec();
        section.extend_from_slice(&(data.len() as u64).to_be_bytes());
        section.extend_from_slice(&compressed);

        let image = crate::elf::Image::load(&std::env::current_exe().unwrap()).unwrap();
        let elf = image.parse().unwrap();
        let (declared, payload) = compressed_payload(&elf, &section, true).unwrap();
        assert_eq!(decompress(payload, declared).unwrap(), data);
    }

    #[test]
    fn rejects_decompressed_size_mismatch() {
        let data = b"DWARF";
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();

        assert!(matches!(
            decompress(&compressed, data.len() as u64 + 1),
            Err(DwarfLayoutError::Invalid(reason))
                if reason.contains("decompressed size")
        ));
    }

    #[test]
    fn ignores_dwarf_sections_not_used_for_layout() {
        assert!(is_layout_section(".debug_info"));
        assert!(is_layout_section(".debug_str"));
        assert!(!is_layout_section(".debug_macro"));
        assert!(!is_layout_section(".debug_loclists"));
    }

    fn valid_index(count_kind: TypeKind, count_width: u64, entry_bins: u64) -> TypeIndex {
        let mut index = TypeIndex::default();
        index.candidates.insert(
            Target::MallocState,
            vec![Structure {
                byte_size: 112,
                members: vec![
                    member("fastbinsY", 16, array_type(TypeKind::Pointer, 8, 10)),
                    member("top", 96, scalar_type(TypeKind::Pointer, 8)),
                    member("next", 104, scalar_type(TypeKind::Pointer, 8)),
                ],
            }],
        );
        index.candidates.insert(
            Target::MallocPar,
            vec![Structure {
                byte_size: 24,
                members: vec![
                    member("arena_max", 0, scalar_type(TypeKind::Unsigned, 8)),
                    member("sbrk_base", 8, scalar_type(TypeKind::Pointer, 8)),
                    member("tcache_bins", 16, scalar_type(TypeKind::Unsigned, 8)),
                ],
            }],
        );
        index.candidates.insert(
            Target::HeapInfo,
            vec![Structure {
                byte_size: 32,
                members: vec![
                    member("ar_ptr", 0, scalar_type(TypeKind::Pointer, 8)),
                    member("prev", 8, scalar_type(TypeKind::Pointer, 8)),
                    member("size", 16, scalar_type(TypeKind::Unsigned, 8)),
                    member("mprotect_size", 24, scalar_type(TypeKind::Unsigned, 8)),
                ],
            }],
        );
        let entries_offset = count_width * 64;
        index.candidates.insert(
            Target::Tcache,
            vec![Structure {
                byte_size: entries_offset + entry_bins * 8,
                members: vec![
                    member("counts", 0, array_type(count_kind, count_width, 64)),
                    member(
                        "entries",
                        entries_offset,
                        array_type(TypeKind::Pointer, 8, entry_bins),
                    ),
                ],
            }],
        );
        index
    }

    fn member(name: &str, offset: u64, ty: TypeInfo) -> Member {
        Member {
            name: name.to_string(),
            offset,
            ty,
        }
    }

    fn scalar_type(kind: TypeKind, byte_size: u64) -> TypeInfo {
        TypeInfo {
            kind,
            byte_size: Some(byte_size),
            element_kind: None,
            element_size: None,
            element_count: None,
        }
    }

    fn array_type(element_kind: TypeKind, element_size: u64, count: u64) -> TypeInfo {
        TypeInfo {
            kind: TypeKind::Array,
            byte_size: Some(element_size * count),
            element_kind: Some(element_kind),
            element_size: Some(element_size),
            element_count: Some(count),
        }
    }
}
