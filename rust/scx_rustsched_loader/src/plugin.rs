// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Load-time composition. No provider table is ever populated: only the
//! final host table receives program FDs, once, before registration.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
};

use anyhow::{Context, Result, bail, ensure};
use libbpf_rs::libbpf_sys as sys;
use libbpf_rs::{
    AsRawLibbpf, Btf, MapCore, MapFlags, MapType, Object, OpenObject, ProgramType,
    btf::{
        BtfType, HasSize,
        types::{Composite, Ptr, Struct},
    },
};
use object::{Object as _, ObjectSection};

use crate::{RunOptions, member};

const PROTECTED: &[&str] = &[
    "init",
    "exit",
    "init_task",
    "exit_task",
    "enable",
    "dequeue",
    "dispatch",
    "update_idle",
];

/// Match the host's topology ABI before opening a provider with libbpf.
/// Raw ELF providers remain supported. Archives contain complete objects,
/// not code to link: only the selected member reaches libbpf.
fn select_object(bytes: &[u8], sized: bool) -> Result<&[u8]> {
    if bytes.starts_with(b"\x7fELF") {
        return Ok(bytes);
    }
    let archive = object::read::archive::ArchiveFile::parse(bytes)
        .context("plugin must be an ELF object or an ar archive")?;
    ensure!(!archive.is_thin(), "thin plugin archives are not supported");
    let mut objects = [None; 2];
    for member in archive.members() {
        let member = member.context("read plugin archive member")?;
        let index = match member.name() {
            b"legacy.bpf.o" => 0,
            b"sized.bpf.o" => 1,
            _ => bail!("unexpected plugin archive member"),
        };
        ensure!(objects[index].is_none(), "duplicate plugin archive variant");
        let data = member.data(bytes).context("read plugin variant")?;
        ensure!(
            data.starts_with(b"\x7fELF"),
            "plugin variant is not an ELF object"
        );
        objects[index] = Some(data);
    }
    objects[usize::from(sized)].with_context(|| {
        format!(
            "plugin archive has no {} topology variant",
            if sized { "sized" } else { "legacy" }
        )
    })
}

/// A host contract and a plugin manifest use the same format. Callback
/// and map lists are exports in the host and imports in the plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub host: String,
    pub contract: u32,
    pub runtime: u32,
    pub callbacks: BTreeSet<String>,
    pub maps: BTreeSet<String>,
    /// Named scalar counters in private plugin maps.
    pub counters: BTreeMap<String, String>,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self> {
        let mut scalar = BTreeMap::new();
        let mut callbacks = BTreeSet::new();
        let mut maps = BTreeSet::new();
        let mut counters = BTreeMap::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
        {
            let (key, value) = line
                .split_once('=')
                .context("manifest entry needs key=value")?;
            ensure!(!value.is_empty(), "empty manifest {key}");
            match key {
                "counter" => {
                    let (name, section) =
                        value.split_once(':').context("counter needs name:map")?;
                    ensure!(
                        !name.is_empty()
                            && name
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_.".contains(&c)),
                        "invalid counter name {name}"
                    );
                    ensure!(
                        section.starts_with(".data.plugin")
                            || section.starts_with(".bss.plugin")
                            || section.starts_with("plugin_"),
                        "counter must use a private plugin map"
                    );
                    ensure!(
                        counters
                            .insert(name.to_owned(), section.to_owned())
                            .is_none(),
                        "duplicate counter {name}"
                    );
                }
                "callback" => {
                    ensure!(
                        callbacks.insert(value.to_owned()),
                        "duplicate callback {value}"
                    );
                }
                "map" => {
                    ensure!(maps.insert(value.to_owned()), "duplicate map {value}");
                }
                "format" | "host" | "contract" | "runtime" => {
                    ensure!(
                        scalar.insert(key, value).is_none(),
                        "duplicate manifest {key}"
                    );
                }
                _ => bail!("unknown manifest key {key}"),
            }
        }
        ensure!(
            scalar.get("format") == Some(&"1"),
            "unsupported plugin manifest format"
        );
        let get = |key| {
            scalar
                .get(key)
                .copied()
                .with_context(|| format!("missing manifest {key}"))
        };
        ensure!(!callbacks.is_empty(), "plugin declares no callbacks");
        for name in &callbacks {
            ensure!(
                name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "invalid callback {name}"
            );
            ensure!(
                !PROTECTED.contains(&name.as_str()),
                "callback {name} owns runtime lifecycle work"
            );
        }
        for name in &maps {
            ensure!(
                !name.contains('*') || name == ".rodata.param.*",
                "unsupported map pattern {name}"
            );
        }
        Ok(Self {
            host: get("host")?.to_owned(),
            contract: get("contract")?.parse()?,
            runtime: get("runtime")?.parse()?,
            callbacks,
            maps,
            counters,
        })
    }

    fn imports(&self, name: &str) -> bool {
        self.maps.contains(name)
            || (name.starts_with(".rodata.param.") && self.maps.contains(".rodata.param.*"))
    }

    fn accepts(&self, plugin: &Self) -> Result<()> {
        ensure!(
            self.host == plugin.host,
            "plugin targets {}, host is {}",
            plugin.host,
            self.host
        );
        ensure!(
            self.contract == plugin.contract,
            "plugin host contract {} != {}",
            plugin.contract,
            self.contract
        );
        ensure!(
            self.runtime == crate::config::PLUGIN_ABI && plugin.runtime == self.runtime,
            "plugin runtime ABI mismatch"
        );
        ensure!(
            plugin.callbacks.is_subset(&self.callbacks),
            "plugin requests a callback the host does not export"
        );
        ensure!(
            plugin.maps.is_subset(&self.maps),
            "plugin requests state the host does not export"
        );
        Ok(())
    }
}

fn kernel_member(callback: &str, ops: Struct<'_>) -> String {
    let field = if callback == "yield_task" {
        "yield"
    } else {
        callback
    };
    if let Some(suffix) = field.strip_prefix("cgroup_") {
        let renamed = format!("cpuctl_{suffix}");
        if Composite::from(ops)
            .iter()
            .any(|m| m.name == Some(OsStr::new(&renamed)))
        {
            return renamed;
        }
    }
    field.to_owned()
}

struct Pending {
    path: PathBuf,
    manifest: Manifest,
    object: OpenObject,
}

/// Validated objects, with no loaded programs or maps yet.
pub(crate) struct Plan {
    plugins: Vec<Pending>,
}

/// Objects stay alive with the host's Loaded handle, including its mmaped
/// arena and any statistics readers. The link is dropped first by run().
#[derive(Default)]
pub(crate) struct Providers {
    pub objects: Vec<Object>,
    pub callbacks: BTreeMap<String, usize>,
    pub counters: BTreeMap<String, (usize, String)>,
}

impl Plan {
    pub fn open(contract: Option<&str>, options: &RunOptions, sized: bool) -> Result<Self> {
        let contract =
            Manifest::parse(contract.context("this scheduler does not export a plugin contract")?)?;
        let mut claimed = BTreeSet::new();
        let mut counters = BTreeSet::new();
        let mut plugins = Vec::new();
        for path in &options.plugins {
            let bytes =
                std::fs::read(path).with_context(|| format!("read plugin {}", path.display()))?;
            let bytes = select_object(&bytes, sized)
                .with_context(|| format!("select plugin variant {}", path.display()))?;
            let elf = object::File::parse(bytes).context("read plugin ELF")?;
            let metadata = elf
                .section_by_name(".scx.plugin")
                .context("plugin has no .scx.plugin manifest")?
                .data()?;
            let manifest = Manifest::parse(std::str::from_utf8(metadata)?.trim_end_matches('\0'))?;
            contract
                .accepts(&manifest)
                .with_context(|| format!("plugin {}", path.display()))?;
            for callback in &manifest.callbacks {
                ensure!(
                    claimed.insert(callback.clone()),
                    "multiple plugins replace {callback}"
                );
            }
            for name in manifest.counters.keys() {
                ensure!(
                    counters.insert(name.clone()),
                    "multiple plugins export counter {name}"
                );
            }
            let object = crate::open("scx_plugin", bytes, &options.libbpf, options.verbose)?;
            plugins.push(Pending {
                path: path.clone(),
                manifest,
                object,
            });
        }
        Ok(Self { plugins })
    }

    pub fn load(self, host: &Object) -> Result<Providers> {
        let mut providers = Providers::default();
        let kernel = Btf::from_vmlinux()?;
        let ops = kernel
            .type_by_name::<Struct<'_>>("sched_ext_ops_cid")
            .context("kernel has no CID struct_ops")?;
        for mut plugin in self.plugins {
            let mut found = BTreeSet::new();
            // libbpf uses the plugin's partial table to derive verifier
            // targets. That table is never populated or registered.
            for mut program in plugin.object.progs_mut() {
                let name = program
                    .name()
                    .to_str()
                    .context("non-UTF8 plugin program")?
                    .to_owned();
                // The runtime emits this userspace topology probe even in
                // a plugin. Only the host loader runs it.
                if name == "rust_cpu_priority" && program.section() == OsStr::new("syscall") {
                    program.set_autoload(false);
                    continue;
                }
                let callback = name
                    .strip_prefix("scx_")
                    .with_context(|| format!("unexpected plugin program {name}"))?;
                ensure!(
                    plugin.manifest.callbacks.contains(callback),
                    "undeclared plugin program {name}"
                );
                let field = kernel_member(callback, ops);
                ensure!(
                    Composite::from(ops)
                        .iter()
                        .any(|m| m.name == Some(OsStr::new(&field))),
                    "kernel lacks callback {callback}"
                );
                ensure!(
                    program.prog_type() == ProgramType::StructOps,
                    "{name} is not struct_ops"
                );
                found.insert(callback.to_owned());
            }
            ensure!(
                found == plugin.manifest.callbacks,
                "plugin callback missing from ELF"
            );
            // SAFETY: the object owns its BTF until after map validation.
            let plugin_btf =
                unsafe { sys::bpf_object__btf(plugin.object.as_libbpf_object().as_ptr()) };
            let host_btf = host.btf()?.context("host map BTF")?;
            for mut map in plugin.object.maps_mut() {
                let name = map
                    .name()
                    .to_str()
                    .context("non-UTF8 plugin map")?
                    .to_owned();
                if map.map_type() == MapType::StructOps {
                    continue;
                }
                if plugin.manifest.imports(&name) {
                    let source = host
                        .maps()
                        .find(|m| m.name() == OsStr::new(&name))
                        .with_context(|| format!("host has no imported map {name}"))?;
                    // Resizable runtime maps get the host's final dimensions.
                    map.set_max_entries(source.max_entries())?;
                    if name == ".data.uei_dump" {
                        map.set_value_size(source.value_size())?;
                    }
                    validate_map(
                        &map,
                        &source,
                        plugin_btf,
                        host_btf.as_libbpf_object().as_ptr(),
                    )?;
                    map.reuse_fd(source.as_fd())
                        .with_context(|| format!("reuse plugin map {name}"))?;
                } else {
                    // Read-only literals are private. All mutable runtime
                    // state must be explicitly imported, or deliberately
                    // named as plugin-private state.
                    ensure!(
                        ((name == ".rodata"
                            || name.ends_with(".rodata")
                            || name.starts_with(".rodata.plugin"))
                            && map.map_flags() & sys::BPF_F_RDONLY_PROG != 0)
                            || name.starts_with(".data.plugin")
                            || name.starts_with(".bss.plugin")
                            || name.starts_with("plugin_"),
                        "undeclared plugin map {name}"
                    );
                }
            }
            let object = plugin
                .object
                .load()
                .with_context(|| format!("load plugin {}", plugin.path.display()))?;
            for (name, section) in plugin.manifest.counters {
                let map = object
                    .maps()
                    .find(|map| map.name() == OsStr::new(&section))
                    .with_context(|| format!("missing counter map {section}"))?;
                ensure!(
                    map.map_type() == MapType::Array
                        && map.key_size() == 4
                        && map.value_size() == 8
                        && map.max_entries() == 1,
                    "counter {name} must be a single u64 array value"
                );
                providers
                    .counters
                    .insert(name, (providers.objects.len(), section));
            }
            for callback in plugin.manifest.callbacks {
                log::info!("plugin {}: {callback}", plugin.path.display());
                providers
                    .callbacks
                    .insert(callback, providers.objects.len());
            }
            providers.objects.push(object);
        }
        Ok(providers)
    }
}

fn validate_map(
    plugin: &libbpf_rs::OpenMapMut<'_>,
    host: &libbpf_rs::Map<'_>,
    plugin_btf: *const sys::btf,
    host_btf: *const sys::btf,
) -> Result<()> {
    let pp = plugin.as_libbpf_object().as_ptr();
    let hp = host.as_libbpf_object().as_ptr();
    // SAFETY: map handles remain alive throughout validation. Comparing
    // BTF as well as sizes rejects same-sized incompatible state layouts.
    unsafe {
        ensure!(
            plugin.map_type() == host.map_type()
                && plugin.key_size() == host.key_size()
                && plugin.value_size() == host.value_size()
                && plugin.map_flags() == sys::bpf_map__map_flags(hp)
                && sys::bpf_map__map_extra(pp) == sys::bpf_map__map_extra(hp),
            "incompatible imported map {:?}",
            plugin.name()
        );
        for (p, h) in [
            (
                sys::bpf_map__btf_key_type_id(pp),
                sys::bpf_map__btf_key_type_id(hp),
            ),
            (
                sys::bpf_map__btf_value_type_id(pp),
                sys::bpf_map__btf_value_type_id(hp),
            ),
        ] {
            ensure!(
                same_type(plugin_btf, p, host_btf, h, &mut BTreeSet::new())?,
                "imported map {:?} has a different BTF layout",
                plugin.name()
            );
        }
    }
    Ok(())
}

// BTF type IDs are local to an object. Compare the graph, including field
// names, offsets, integer encodings and array bounds, rather than IDs.
// Opaque arena contents are covered by the host contract version.
unsafe fn same_type(
    a: *const sys::btf,
    ai: u32,
    b: *const sys::btf,
    bi: u32,
    seen: &mut BTreeSet<(u32, u32)>,
) -> Result<bool> {
    if ai == 0 || bi == 0 {
        return Ok(ai == bi);
    }
    if !seen.insert((ai, bi)) {
        return Ok(true);
    }
    // SAFETY: libbpf validates the BTF when opening each object. Every
    // trailing record is bounded by the validated type's vlen and kind.
    unsafe {
        let at = sys::btf__type_by_id(a, ai)
            .as_ref()
            .context("invalid plugin BTF ID")?;
        let bt = sys::btf__type_by_id(b, bi)
            .as_ref()
            .context("invalid host BTF ID")?;
        let kind = |t: &sys::btf_type| (t.info >> 24) & 0x1f;
        let ak = kind(at);
        let bk = kind(bt);
        let modifier = |k| matches!(k, 8..=11 | 18);
        if modifier(ak) {
            return same_type(a, at.__bindgen_anon_1.type_, b, bi, seen);
        }
        if modifier(bk) {
            return same_type(a, ai, b, bt.__bindgen_anon_1.type_, seen);
        }
        if at.info != bt.info {
            return Ok(false);
        }
        let names_equal = |an, bn| -> Result<bool> {
            let ap = sys::btf__name_by_offset(a, an);
            let bp = sys::btf__name_by_offset(b, bn);
            ensure!(!ap.is_null() && !bp.is_null(), "invalid BTF name");
            Ok(std::ffi::CStr::from_ptr(ap) == std::ffi::CStr::from_ptr(bp))
        };
        if !names_equal(at.name_off, bt.name_off)? {
            return Ok(false);
        }
        let ap = (at as *const sys::btf_type).add(1).cast::<u32>();
        let bp = (bt as *const sys::btf_type).add(1).cast::<u32>();
        let count = (at.info & 0xffff) as usize;
        match ak {
            1 => Ok(at.__bindgen_anon_1.size == bt.__bindgen_anon_1.size && *ap == *bp),
            2 | 12 | 14 => {
                if ak == 14 && *ap != *bp {
                    return Ok(false);
                }
                same_type(
                    a,
                    at.__bindgen_anon_1.type_,
                    b,
                    bt.__bindgen_anon_1.type_,
                    seen,
                )
            }
            3 => Ok(*ap.add(2) == *bp.add(2)
                && same_type(a, *ap, b, *bp, seen)?
                && same_type(a, *ap.add(1), b, *bp.add(1), seen)?),
            4 | 5 | 15 => {
                if at.__bindgen_anon_1.size != bt.__bindgen_anon_1.size {
                    return Ok(false);
                }
                for i in 0..count {
                    let x = ap.add(3 * i);
                    let y = bp.add(3 * i);
                    if ak == 15 {
                        if *x.add(1) != *y.add(1)
                            || *x.add(2) != *y.add(2)
                            || !same_type(a, *x, b, *y, seen)?
                        {
                            return Ok(false);
                        }
                    } else if !names_equal(*x, *y)?
                        || *x.add(2) != *y.add(2)
                        || !same_type(a, *x.add(1), b, *y.add(1), seen)?
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            6 | 19 => {
                if at.__bindgen_anon_1.size != bt.__bindgen_anon_1.size {
                    return Ok(false);
                }
                let stride = if ak == 6 { 2 } else { 3 };
                for i in 0..count {
                    if !names_equal(*ap.add(stride * i), *bp.add(stride * i))? {
                        return Ok(false);
                    }
                    for j in 1..stride {
                        if *ap.add(stride * i + j) != *bp.add(stride * i + j) {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            }
            7 | 16 => Ok(at.__bindgen_anon_1.size == bt.__bindgen_anon_1.size),
            _ => bail!("unsupported shared BTF kind {ak}"),
        }
    }
}

/// Save the host's shadow table before load. It contains libbpf program
/// pointers, not program FDs. Resolve them while the OpenObject is alive.
pub(crate) struct Table {
    fields: BTreeMap<String, Vec<u8>>,
    callbacks: BTreeMap<String, String>,
}

impl Table {
    pub fn capture(open: &mut OpenObject, bytes: &[u8], ops: &str) -> Result<Self> {
        let programs: BTreeMap<_, _> = open
            .progs()
            .map(|p| {
                (
                    p.as_libbpf_object().as_ptr() as usize as u64,
                    p.name().to_string_lossy().into_owned(),
                )
            })
            .collect();
        let btf = Btf::from_raw("host", bytes)?.context("host BTF")?;
        let structure = btf
            .type_by_name::<Struct<'_>>(crate::ops_type(ops))
            .context("host ops type")?;
        let map = open
            .maps_mut()
            .find(|m| m.name() == OsStr::new(ops))
            .context("host ops map")?;
        let data = map.initial_value().context("host shadow table")?;
        let mut fields = BTreeMap::new();
        let mut callbacks = BTreeMap::new();
        for entry in Composite::from(structure).iter() {
            let name = entry
                .name
                .context("anonymous ops field")?
                .to_str()
                .context("ops field name")?;
            let (ty, offset) = member(&btf, structure, name)?;
            let offset = offset as usize;
            if Ptr::try_from(ty).is_ok() {
                let pointer = u64::from_ne_bytes(
                    data.get(offset..offset + 8)
                        .context("callback outside shadow table")?
                        .try_into()?,
                );
                if pointer != 0 {
                    callbacks.insert(
                        name.to_owned(),
                        programs
                            .get(&pointer)
                            .context("unresolved host callback")?
                            .clone(),
                    );
                }
            } else {
                let size = type_size(&btf, ty)?;
                fields.insert(
                    name.to_owned(),
                    data.get(offset..offset + size)
                        .context("field outside shadow table")?
                        .to_vec(),
                );
            }
        }
        Ok(Self { fields, callbacks })
    }

    pub fn populate(&self, host: &Object, providers: &Providers, ops_name: &str) -> Result<()> {
        let kernel = Btf::from_vmlinux()?;
        let ops = kernel
            .type_by_name::<Struct<'_>>("sched_ext_ops_cid")
            .context("kernel ops")?;
        let wrapper = kernel
            .type_by_name::<Struct<'_>>("bpf_struct_ops_sched_ext_ops_cid")
            .context("kernel ops value")?;
        let (_, base) = member(&kernel, wrapper, "data")?;
        let mut value = vec![0_u8; wrapper.size()];
        for (name, bytes) in &self.fields {
            if let Ok((ty, offset)) = member(&kernel, ops, name) {
                ensure!(
                    type_size(&kernel, ty)? == bytes.len(),
                    "kernel ops field {name} changed size"
                );
                let start = (base + offset) as usize;
                value[start..start + bytes.len()].copy_from_slice(bytes);
            } else {
                ensure!(
                    bytes.iter().all(|b| *b == 0),
                    "kernel lacks nonzero ops field {name}"
                );
            }
        }
        let mut callbacks: BTreeMap<_, _> = self
            .callbacks
            .iter()
            .map(|(member, symbol)| (member.clone(), (symbol.clone(), None)))
            .collect();
        for (callback, provider) in &providers.callbacks {
            callbacks.insert(
                kernel_member(callback, ops),
                (format!("scx_{callback}"), Some(*provider)),
            );
        }
        for (callback, (symbol, provider)) in callbacks {
            let source = provider.map_or(host, |index| &providers.objects[index]);
            let program = source
                .progs()
                .find(|p| p.name() == OsStr::new(&symbol))
                .with_context(|| format!("missing program {symbol}"))?;
            let (_, offset) = member(&kernel, ops, &callback)?;
            let start = (base + offset) as usize;
            value[start..start + 8]
                .copy_from_slice(&(program.as_fd().as_raw_fd() as u64).to_ne_bytes());
        }
        let map = host
            .maps()
            .find(|m| m.name() == OsStr::new(ops_name))
            .context("host ops map")?;
        ensure!(
            map.value_size() as usize == value.len(),
            "kernel ops value size mismatch"
        );
        map.update(&0_u32.to_ne_bytes(), &value, MapFlags::ANY)
            .context("populate composed struct_ops")
    }
}

fn type_size(btf: &Btf<'_>, ty: BtfType<'_>) -> Result<usize> {
    // SAFETY: both the BTF pointer and its type ID are live and valid.
    let size =
        unsafe { sys::btf__resolve_size(btf.as_libbpf_object().as_ptr(), ty.type_id().into()) };
    ensure!(size >= 0, "cannot resolve BTF field size");
    Ok(size as usize)
}

pub(crate) fn attach(host: &Object, ops: &str) -> Result<OwnedFd> {
    ensure!(
        !crate::compat::is_sched_ext_enabled().unwrap_or(false),
        "another sched_ext scheduler is already running"
    );
    let map = host
        .maps()
        .find(|m| m.name() == OsStr::new(ops))
        .context("host ops map")?;
    // SAFETY: the populated map is live, opts may be NULL, and a successful
    // syscall returns a new FD owned by this function.
    let fd = unsafe {
        sys::bpf_link_create(
            map.as_fd().as_raw_fd(),
            0,
            sys::BPF_STRUCT_OPS,
            std::ptr::null(),
        )
    };
    ensure!(
        fd >= 0,
        "attach composed struct_ops: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    const HOST: &str =
        "format=1\nhost=test\ncontract=1\nruntime=1\ncallback=select_cid\nmap=arena\n";

    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = b"!<arch>\n".to_vec();
        for (name, data) in members {
            bytes.extend_from_slice(
                format!(
                    "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    format!("{name}/"),
                    0,
                    0,
                    0,
                    "100644",
                    data.len()
                )
                .as_bytes(),
            );
            bytes.extend_from_slice(data);
            if !data.len().is_multiple_of(2) {
                bytes.push(b'\n');
            }
        }
        bytes
    }

    #[test]
    fn selects_topology_variant_before_loading() {
        let legacy = b"\x7fELFlegacy";
        let sized = b"\x7fELFsized";
        let bytes = archive(&[("legacy.bpf.o", legacy), ("sized.bpf.o", sized)]);
        assert_eq!(select_object(&bytes, false).unwrap(), legacy);
        assert_eq!(select_object(&bytes, true).unwrap(), sized);
        assert_eq!(select_object(legacy, false).unwrap(), legacy);
        assert_eq!(select_object(sized, true).unwrap(), sized);
        // Partial archives can be distributed, but never select a variant
        // whose calling convention differs from the host's.
        let partial = archive(&[("legacy.bpf.o", legacy)]);
        assert!(select_object(&partial, false).is_ok());
        assert!(select_object(&partial, true).is_err());
    }

    #[test]
    fn rejects_invalid_or_ambiguous_archives() {
        let elf = b"\x7fELFtest";
        for bytes in [
            b"!<arch>\ntruncated".to_vec(),
            b"not a plugin".to_vec(),
            archive(&[]),
            archive(&[("sized.bpf.o", elf), ("sized.bpf.o", elf)]),
            archive(&[("other.bpf.o", elf)]),
            archive(&[("sized.bpf.o", b"not ELF")]),
        ] {
            assert!(select_object(&bytes, true).is_err());
        }
        let mut truncated = archive(&[("sized.bpf.o", elf)]);
        truncated.truncate(truncated.len() - 4);
        assert!(select_object(&truncated, true).is_err());
    }

    #[test]
    fn reject_incompatible_contracts() {
        let host = Manifest::parse(HOST).unwrap();
        host.accepts(&host).unwrap();
        for (from, to) in [
            ("host=test", "host=other"),
            ("contract=1", "contract=2"),
            ("runtime=1", "runtime=2"),
            ("select_cid", "tick"),
            ("map=arena", "map=private"),
        ] {
            assert!(
                host.accepts(&Manifest::parse(&HOST.replace(from, to)).unwrap())
                    .is_err()
            );
        }
    }

    #[test]
    fn counters_are_plugin_metadata_not_host_policy() {
        let host = Manifest::parse(HOST).unwrap();
        let plugin = Manifest::parse(&format!(
            "{HOST}counter=example.events:.data.plugin_events\n"
        ))
        .unwrap();
        host.accepts(&plugin).unwrap();
        assert_eq!(plugin.counters["example.events"], ".data.plugin_events");
        for entry in [
            "counter=events:arena",
            "counter=:plugin_events",
            "counter=events",
            "counter=bad name:plugin_events",
        ] {
            assert!(Manifest::parse(&format!("{HOST}{entry}\n")).is_err());
        }
        assert!(
            Manifest::parse(&format!(
                "{HOST}counter=events:plugin_events\ncounter=events:plugin_other\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn reject_ambiguous_or_protected_entries() {
        for text in [
            format!("{HOST}contract=1\n"),
            format!("{HOST}callback=select_cid\n"),
            HOST.replace("select_cid", "init_task"),
            format!("{HOST}unknown=1\n"),
            HOST.replace("map=arena", "map=.data.*"),
        ] {
            assert!(Manifest::parse(&text).is_err(), "{text}");
        }
    }

    #[test]
    fn shared_layout_checks_offsets_and_encodings() {
        // Construct BTFs without loading anything into the kernel. The
        // layouts deliberately have equal sizes but incompatible fields.
        unsafe {
            let a = sys::btf__new_empty();
            let b = sys::btf__new_empty();
            assert!(!a.is_null() && !b.is_null());
            let ai = sys::btf__add_int(a, c"word".as_ptr(), 4, 0);
            let bi = sys::btf__add_int(b, c"word".as_ptr(), 4, 0);
            let bs = sys::btf__add_int(b, c"word".as_ptr(), 4, 1);
            let state = |btf, word, offset| {
                let id = sys::btf__add_struct(btf, c"State".as_ptr(), 8);
                assert!(id > 0);
                assert_eq!(
                    sys::btf__add_field(btf, c"counter".as_ptr(), word, offset, 0),
                    0
                );
                id as u32
            };
            let original = state(a, ai, 0);
            let equivalent = state(b, bi, 0);
            let shifted = state(b, bi, 32);
            let signed = state(b, bs, 0);
            assert!(same_type(a, original, b, equivalent, &mut BTreeSet::new()).unwrap());
            assert!(!same_type(a, original, b, shifted, &mut BTreeSet::new()).unwrap());
            assert!(!same_type(a, original, b, signed, &mut BTreeSet::new()).unwrap());
            sys::btf__free(a);
            sys::btf__free(b);
        }
    }
}
