mod libvmi_c;

use std::alloc::{alloc, dealloc, Layout};
use std::ffi::{CStr, CString};

// We sometimes need to free pointers returned by libvmi
use anyhow::{bail, Result};
use libc::{c_void, free};

// Export all libvmi symbols, but provide a nice convenient wrapper too.
pub use libvmi_c::*;

#[inline]
pub fn setup_interrupt_event(
    event: &mut vmi_event_t,
    callback: event_callback_t,
    data: *mut c_void,
) {
    event.version = VMI_EVENTS_VERSION;
    event.type_ = VMI_EVENT_INTERRUPT as u16;
    event.__bindgen_anon_1.interrupt_event.intr = INT3 as u8;
    event
        .__bindgen_anon_1
        .interrupt_event
        .__bindgen_anon_1
        .__bindgen_anon_1
        .reinject = -1;
    event.callback = callback;
    event.data = data;
}

/*
/**
 * Convenience macro to setup a memory event
 */
#define SETUP_MEM_EVENT(_event, _gfn, _access, _callback, _generic) \
        do { \
            (_event)->version = VMI_EVENTS_VERSION; \
            (_event)->type = VMI_EVENT_MEMORY; \
            (_event)->mem_event.gfn = _generic ? ~0ULL :_gfn; \
            (_event)->mem_event.in_access = _access; \
            (_event)->mem_event.generic = _generic; \
            (_event)->callback = _callback; \
        } while(0)
 */

#[inline]
pub fn setup_mem_event(
    event: &mut vmi_event_t,
    gfn: addr_t,
    access: vmi_mem_access_t,
    callback: event_callback_t,
    generic: u8,
) {
    event.version = VMI_EVENTS_VERSION;
    event.type_ = VMI_EVENT_MEMORY as u16;
    event.__bindgen_anon_1.mem_event.gfn = if generic > 0 { !0 } else { gfn };
    event.__bindgen_anon_1.mem_event.in_access = access;
    event.__bindgen_anon_1.mem_event.generic = generic;
    event.callback = callback;
}

/*
#define SETUP_SINGLESTEP_EVENT(_event, _vcpu_mask, _callback, _enable) \
        do { \
            (_event)->version = VMI_EVENTS_VERSION; \
            (_event)->type = VMI_EVENT_SINGLESTEP; \
            (_event)->ss_event.vcpus = _vcpu_mask; \
            (_event)->ss_event.enable = _enable; \
            (_event)->callback = _callback; \
        } while(0)

*/

#[inline]
pub fn setup_singlestep_event(
    event: &mut vmi_event_t,
    vcpu_mask: u32,
    callback: event_callback_t,
    enable: u8,
) {
    event.version = VMI_EVENTS_VERSION;
    event.type_ = VMI_EVENT_SINGLESTEP as u16;
    event.__bindgen_anon_1.ss_event.vcpus = vcpu_mask;
    event.__bindgen_anon_1.ss_event.enable = enable;
    event.callback = callback;
}

/*
/**
 * Convenience macro to setup a register event
 */
#define SETUP_REG_EVENT(_event, _reg, _access, _equal, _callback) \
        do { \
            (_event)->version = VMI_EVENTS_VERSION; \
            (_event)->type = VMI_EVENT_REGISTER; \
            (_event)->reg_event.reg = _reg; \
            (_event)->reg_event.in_access = _access; \
            (_event)->reg_event.equal = _equal; \
            (_event)->callback = _callback; \
        } while(0)

*/
#[inline]
pub fn setup_regs_event(
    event: &mut vmi_event_t,
    reg: reg_t,
    access: vmi_reg_access_t,
    equal: u64,
    callback: event_callback_t,
) {
    event.version = VMI_EVENTS_VERSION;
    event.type_ = VMI_EVENT_REGISTER as u16;
    event.__bindgen_anon_1.reg_event.reg = reg;
    event.__bindgen_anon_1.reg_event.in_access = access;
    event.__bindgen_anon_1.reg_event.equal = equal;
    event.callback = callback;
}

#[inline]
pub fn setup_event_emul_insn(event: *mut vmi_event_t, emul_insn: *mut emul_insn_t) {
    unsafe {
        (*event).__bindgen_anon_2.emul_insn = emul_insn;
    }
}

#[inline]
pub fn get_interrupt_event<'a>(
    event: *mut vmi_event_t,
) -> &'a mut interrupt_event__bindgen_ty_1__bindgen_ty_1 {
    unsafe {
        &mut (*event)
            .__bindgen_anon_1
            .interrupt_event
            .__bindgen_anon_1
            .__bindgen_anon_1
    }
}

#[inline]
pub fn get_mem_event<'a>(event: *mut vmi_event_t) -> &'a mut mem_access_event_t {
    unsafe { &mut (*event).__bindgen_anon_1.mem_event }
}

#[inline]
pub fn get_ss_event<'a>(event: *mut vmi_event_t) -> &'a mut single_step_event_t {
    unsafe { &mut (*event).__bindgen_anon_1.ss_event }
}

//get x86_regs
#[inline]
pub fn get_x86_regs(event: *mut vmi_event_t) -> *mut x86_registers_t {
    unsafe { (*event).__bindgen_anon_2.__bindgen_anon_1.x86_regs }
}

/// A handle on a VM for LibVMI
pub struct VmiInstance {
    /// The libvmi handle type
    vmi: vmi_instance_t,
}

//impl from vmi_instance_t
impl From<vmi_instance_t> for VmiInstance {
    fn from(vmi: vmi_instance_t) -> Self {
        VmiInstance { vmi }
    }
}

//impl into vmi_instance_t
impl Into<vmi_instance_t> for VmiInstance {
    fn into(self) -> vmi_instance_t {
        self.vmi
    }
}

//impl deref to vmi_instance_t
impl std::ops::Deref for VmiInstance {
    type Target = vmi_instance_t;

    fn deref(&self) -> &Self::Target {
        &self.vmi
    }
}

//impl derefmut to vmi_instance_t
impl std::ops::DerefMut for VmiInstance {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vmi
    }
}

impl VmiInstance {
    pub fn new(
        name: &str,
        config_mode: Option<u32>,
        config: Option<&str>,
        socket_path: &str,
    ) -> Result<VmiInstance, vmi_init_error_t> {
        unsafe {
            let mut vmi: vmi_instance_t = std::ptr::null_mut();
            let mut error: vmi_init_error_t = 0;

            // Allocate space for vmi_init_data_t plus one vmi_init_data_entry_t
            let layout = Layout::new::<vmi_init_data_t>()
                .extend(Layout::array::<vmi_init_data_entry_t>(1).unwrap())
                .unwrap()
                .0
                .pad_to_align();
            let init_data_ptr = alloc(layout) as *mut vmi_init_data_t;

            // Initialize the count
            (*init_data_ptr).count = 1;

            // Get a pointer to the memory location immediately after vmi_init_data_t
            let entries_ptr = init_data_ptr.add(1) as *mut vmi_init_data_entry_t;

            let socket_path = CString::new(socket_path).unwrap();
            // Initialize the entry
            std::ptr::write(
                entries_ptr,
                vmi_init_data_entry_t {
                    type_: vmi_init_data_type_t_VMI_INIT_DATA_KVMI_SOCKET as u64,
                    data: socket_path.as_ptr() as *mut _,
                },
            );

            let config_ptr = if let Some(config) = config {
                CString::new(config).unwrap()
            } else {
                CString::default()
            };

            let name = CString::new(name).unwrap();
            // Attempt to initialize a VMI instance handle
            let result = vmi_init_complete(
                &mut vmi as *mut _,
                name.as_ptr() as *mut _,
                (VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS) as u64,
                init_data_ptr as *mut _,
                config_mode.unwrap_or(vmi_config_VMI_CONFIG_GLOBAL_FILE_ENTRY),
                config_ptr.as_ptr() as *mut _,
                &mut error as *mut _,
            );

            dealloc(init_data_ptr as *mut u8, layout);

            // On failure extract the error type
            if result == status_VMI_FAILURE {
                return Err(error);
            }

            // Otherwise, return the handle
            Ok(VmiInstance { vmi })
        }
    }

    pub fn vmi_init_paging(&self) -> Result<()> {
        unsafe {
            if vmi_init_paging(self.vmi, 0) == VMI_PM_UNKNOWN {
                bail!("vmi init error paging")
            }
        }

        Ok(())
    }

    pub fn vmi_init_os(&self, config_mode: Option<u32>, config: Option<&str>) -> Result<()> {
        let mut error: vmi_init_error_t = 0;
        let config_ptr = if let Some(config) = config {
            CString::new(config)?
        } else {
            CString::default()
        };

        unsafe {
            if vmi_init_os(
                self.vmi,
                config_mode.unwrap_or(vmi_config_VMI_CONFIG_GLOBAL_FILE_ENTRY),
                config_ptr.as_ptr() as *mut _,
                &mut error as *mut _,
            ) == os_VMI_OS_UNKNOWN
            {
                bail!("Unable to init os, errcode: {}", error)
            }
        }

        Ok(())
    }

    #[inline]
    pub fn as_mut_ptr(&self) -> vmi_instance_t {
        self.vmi
    }

    #[inline]
    pub fn vmi_get_os_type(&self) -> os_t {
        unsafe { vmi_get_ostype(self.vmi) }
    }

    #[inline]
    pub fn vmi_get_winver(&self) -> win_ver_t {
        unsafe { vmi_get_winver(self.vmi) }
    }

    #[inline]
    pub fn vmi_get_address_width(&self) -> u8 {
        unsafe { vmi_get_address_width(self.vmi) }
    }

    #[inline]
    pub fn vmi_get_page_mode(&self, vcpu: ::std::os::raw::c_ulong) -> page_mode_t {
        unsafe { vmi_get_page_mode(self.vmi, vcpu) }
    }

    pub fn vmi_get_access_mode(&self) -> Result<vmi_mode_t> {
        unsafe {
            let mut vmi_mode: vmi_mode_t = 0;
            if vmi_get_access_mode(
                self.vmi,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut vmi_mode as *mut _,
            ) == status_VMI_FAILURE
            {
                bail!("Unable to get access mode")
            } else {
                Ok(vmi_mode)
            }
        }
    }

    //vmi_get_vcpureg
    pub fn vmi_get_vcpureg(&self, reg: reg_t, vcpu: ::std::os::raw::c_ulong) -> Result<u64> {
        unsafe {
            let mut value: u64 = 0;
            if vmi_get_vcpureg(self.vmi, &mut value as *mut _, reg, vcpu) == status_VMI_FAILURE {
                bail!("Unable to get vcpu register")
            } else {
                Ok(value)
            }
        }
    }

    //vmi_pagecache_flush
    #[inline]
    pub fn vmi_pagecache_flush(&self) {
        unsafe { vmi_pagecache_flush(self.vmi) }
    }

    //vmi_pagetable_lookup
    pub fn vmi_pagetable_lookup(&self, pt: addr_t, vaddr: addr_t) -> Result<addr_t> {
        unsafe {
            let mut value: addr_t = 0;
            if vmi_pagetable_lookup(self.vmi, pt, vaddr, &mut value as *mut _) == status_VMI_FAILURE
            {
                bail!("Unable to lookup page table")
            } else {
                Ok(value)
            }
        }
    }

    pub fn vmi_get_offset(&self, offset_name: &str) -> Result<addr_t> {
        unsafe {
            let offset_name = CString::new(offset_name)?;
            let mut offset: addr_t = 0u64;
            if vmi_get_offset(
                self.vmi,
                offset_name.as_ptr() as *mut _,
                &mut offset as *mut _,
            ) == status_VMI_FAILURE
            {
                bail!("Unable to get offset \"{:?}\" from config", offset_name)
            } else {
                Ok(offset)
            }
        }
    }

    pub fn vmi_get_kernel_struct_offset(
        &self,
        struct_name: &str,
        member_name: &str,
    ) -> Result<addr_t> {
        let mut addr: addr_t = 0;
        unsafe {
            let struct_name = CString::new(struct_name)?;
            let member_name = CString::new(member_name)?;
            if vmi_get_kernel_struct_offset(
                self.vmi,
                struct_name.as_ptr(),
                member_name.as_ptr(),
                &mut addr,
            ) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to get kernel struct offset \"{:?}\" \"{:?}\"",
                    struct_name,
                    member_name
                )
            }
        }

        Ok(addr)
    }

    pub fn vmi_pause_vm(&self) -> Result<()> {
        unsafe {
            if vmi_pause_vm(self.vmi) == status_VMI_FAILURE {
                bail!("Unable to pause vm")
            } else {
                Ok(())
            }
        }
    }

    pub fn vmi_resume_vm(&self) -> Result<()> {
        unsafe {
            if vmi_resume_vm(self.vmi) == status_VMI_FAILURE {
                bail!("Unable to resume vm")
            } else {
                Ok(())
            }
        }
    }

    pub fn vmi_translate_ksym2v(&self, name: &str) -> Result<addr_t> {
        unsafe {
            let name = CString::new(name)?;
            let mut addr: addr_t = 0;
            if vmi_translate_ksym2v(self.vmi, name.as_ptr() as *mut _, &mut addr as *mut _)
                == status_VMI_FAILURE
            {
                bail!("Unable to translate kernel symbol \"{:?}\" to va", name)
            } else {
                Ok(addr)
            }
        }
    }

    pub fn vmi_translate_kv2p(&self, vaddr: addr_t) -> Result<addr_t> {
        unsafe {
            let mut addr: addr_t = 0;
            if vmi_translate_kv2p(self.vmi, vaddr, &mut addr as *mut _) == status_VMI_FAILURE {
                bail!(
                    "Unable to translate kernel virtual address 0x{:X} to physical address",
                    vaddr
                )
            } else {
                Ok(addr)
            }
        }
    }

    //vmi_translate_uv2p
    pub fn vmi_translate_uv2p(&self, vaddr: addr_t, pid: i32) -> Result<addr_t> {
        unsafe {
            let mut addr: addr_t = 0;
            if vmi_translate_uv2p(self.vmi, vaddr, pid as _, &mut addr as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to translate user virtual address 0x{:X} to physical address for PID {}",
                    vaddr,
                    pid
                )
            } else {
                Ok(addr)
            }
        }
    }

    //vmi_translate_sym2v
    pub fn vmi_translate_sym2v(&self, name: &str, pid: i32) -> Result<addr_t> {
        unsafe {
            let name = CString::new(name)?;
            let mut addr: addr_t = 0;
            if vmi_translate_sym2v(
                self.vmi,
                name.as_ptr() as *mut _,
                pid as _,
                &mut addr as *mut _,
            ) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to translate symbol \"{:?}\" to virtual address for PID {}",
                    name,
                    pid
                )
            } else {
                Ok(addr)
            }
        }
    }

    //vmi_set_mem_event
    pub fn vmi_set_mem_event(
        &self,
        gfn: addr_t,
        access: vmi_mem_access_t,
        vmm_pagetable_id: u16,
    ) -> Result<()> {
        unsafe {
            if vmi_set_mem_event(self.vmi, gfn, access, vmm_pagetable_id) == status_VMI_FAILURE {
                bail!("Unable to set memory event")
            } else {
                Ok(())
            }
        }
    }

    //vmi_get_mem_event
    #[inline]
    pub fn vmi_get_mem_event(&self, gfn: addr_t, access: vmi_mem_access_t) -> *mut vmi_event_t {
        unsafe { vmi_get_mem_event(self.vmi, gfn, access) }
    }

    pub fn vmi_register_event(&self, event: &mut vmi_event_t) -> Result<()> {
        unsafe {
            if vmi_register_event(self.vmi, event as *mut _) == status_VMI_FAILURE {
                bail!("Unable to register event")
            } else {
                Ok(())
            }
        }
    }

    //vmi_clear_event
    pub fn vmi_clear_event(&self, event: &mut vmi_event_t) -> Result<()> {
        unsafe {
            if vmi_clear_event(self.vmi, event as *mut _, None) == status_VMI_FAILURE {
                bail!("Unable to clear event")
            } else {
                Ok(())
            }
        }
    }

    //vmi_step_event
    pub fn vmi_step_event(
        &self,
        event: &mut vmi_event_t,
        vcpu_id: u32,
        steps: u64,
        cb: event_callback_t,
    ) -> Result<()> {
        unsafe {
            if vmi_step_event(self.vmi, event as *mut _, vcpu_id, steps, cb) == status_VMI_FAILURE {
                bail!("Unable to step event")
            } else {
                Ok(())
            }
        }
    }

    pub fn vmi_events_listen(&self, timeout: u32) -> Result<()> {
        unsafe {
            if vmi_events_listen(self.vmi, timeout) == status_VMI_FAILURE {
                bail!("Unable to listen for events")
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_ksym
    pub fn vmi_write_ksym(&self, name: &str, buf: &[u8]) -> Result<()> {
        unsafe {
            let name = CString::new(name)?;
            let mut bytes_written: usize = 0;
            if vmi_write_ksym(
                self.vmi,
                name.as_ptr() as *mut _,
                buf.len(),
                buf.as_ptr() as *mut _,
                &mut bytes_written as *mut _,
            ) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write {} bytes to kernel symbol \"{:?}\"",
                    buf.len(),
                    name
                )
            } else {
                Ok(())
            }
        }
    }

    pub fn vmi_write_va(&self, vaddr: addr_t, pid: i32, buf: &[u8]) -> Result<()> {
        unsafe {
            let mut bytes_written: usize = 0;
            if vmi_write_va(
                self.vmi,
                vaddr,
                pid as _,
                buf.len(),
                buf.as_ptr() as *mut _,
                &mut bytes_written as *mut _,
            ) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write {} bytes to address 0x{:X} for PID {}",
                    buf.len(),
                    vaddr,
                    pid
                )
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_pa
    pub fn vmi_write_pa(&self, paddr: addr_t, buf: &[u8]) -> Result<()> {
        unsafe {
            let mut bytes_written: usize = 0;
            if vmi_write_pa(
                self.vmi,
                paddr,
                buf.len(),
                buf.as_ptr() as *mut _,
                &mut bytes_written as *mut _,
            ) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write {} bytes to physical address 0x{:X}",
                    buf.len(),
                    paddr
                )
            } else {
                Ok(())
            }
        }
    }
    //vmi_write_8_va
    pub fn vmi_write_8_va(&self, vaddr: addr_t, pid: i32, value: u8) -> Result<()> {
        unsafe {
            if vmi_write_8_va(self.vmi, vaddr, pid as _, &value as *const _ as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write u8 value 0x{:X} to address 0x{:X} for PID {}",
                    value,
                    vaddr,
                    pid
                )
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_16_va
    pub fn vmi_write_16_va(&self, vaddr: addr_t, pid: i32, value: u16) -> Result<()> {
        unsafe {
            if vmi_write_16_va(self.vmi, vaddr, pid as _, &value as *const _ as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write u16 value 0x{:X} to address 0x{:X} for PID {}",
                    value,
                    vaddr,
                    pid
                )
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_32_va
    pub fn vmi_write_32_va(&self, vaddr: addr_t, pid: i32, value: u32) -> Result<()> {
        unsafe {
            if vmi_write_32_va(self.vmi, vaddr, pid as _, &value as *const _ as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write u32 value 0x{:X} to address 0x{:X} for PID {}",
                    value,
                    vaddr,
                    pid
                )
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_64_va
    pub fn vmi_write_64_va(&self, vaddr: addr_t, pid: i32, value: u64) -> Result<()> {
        unsafe {
            if vmi_write_64_va(self.vmi, vaddr, pid as _, &value as *const _ as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write u64 value 0x{:X} to address 0x{:X} for PID {}",
                    value,
                    vaddr,
                    pid
                )
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_addr_va
    pub fn vmi_write_addr_va(&self, vaddr: addr_t, pid: i32, value: addr_t) -> Result<()> {
        unsafe {
            if vmi_write_addr_va(self.vmi, vaddr, pid as _, &value as *const _ as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write addr value 0x{:X} to address 0x{:X} for PID {}",
                    value,
                    vaddr,
                    pid
                )
            } else {
                Ok(())
            }
        }
    }

    pub fn vmi_write_8_pa(&self, paddr: addr_t, value: u8) -> Result<()> {
        unsafe {
            if vmi_write_8_pa(self.vmi, paddr, &value as *const _ as *mut _) == status_VMI_FAILURE {
                bail!(
                    "Unable to write u8 value 0x{:X} to physical address 0x{:X}",
                    value,
                    paddr
                )
            } else {
                Ok(())
            }
        }
    }

    // vmi_write_16_pa
    pub fn vmi_write_16_pa(&self, paddr: addr_t, value: u16) -> Result<()> {
        unsafe {
            if vmi_write_16_pa(self.vmi, paddr, &value as *const _ as *mut _) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write u16 value 0x{:X} to physical address 0x{:X}",
                    value,
                    paddr
                )
            } else {
                Ok(())
            }
        }
    }

    // vmi_write_32_pa
    pub fn vmi_write_32_pa(&self, paddr: addr_t, value: u32) -> Result<()> {
        unsafe {
            if vmi_write_32_pa(self.vmi, paddr, &value as *const _ as *mut _) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write u32 value 0x{:X} to physical address 0x{:X}",
                    value,
                    paddr
                )
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_64_pa
    pub fn vmi_write_64_pa(&self, paddr: addr_t, value: u64) -> Result<()> {
        unsafe {
            if vmi_write_64_pa(self.vmi, paddr, &value as *const _ as *mut _) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write u64 value 0x{:X} to physical address 0x{:X}",
                    value,
                    paddr
                )
            } else {
                Ok(())
            }
        }
    }

    //vmi_write_addr_pa
    pub fn vmi_write_addr_pa(&self, paddr: addr_t, value: addr_t) -> Result<()> {
        unsafe {
            if vmi_write_addr_pa(self.vmi, paddr, &value as *const _ as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to write addr value 0x{:X} to physical address 0x{:X}",
                    value,
                    paddr
                )
            } else {
                Ok(())
            }
        }
    }

    pub fn vmi_read_va(&self, vaddr: addr_t, pid: i32, count: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut buf: Vec<u8> = vec![0; count];
            let mut bytes_read: usize = 0;

            if vmi_read_va(
                self.vmi,
                vaddr,
                pid as _,
                count,
                buf.as_mut_ptr() as *mut _,
                &mut bytes_read as *mut _,
            ) == status_VMI_FAILURE
            {
                bail!(
                    "Unable to read {} bytes from address 0x{:X} for PID {}",
                    count,
                    vaddr,
                    pid
                )
            } else {
                buf.truncate(bytes_read);
                Ok(buf)
            }
        }
    }

    pub fn vmi_read_addr_va(&self, vaddr: addr_t, pid: i32) -> Result<addr_t> {
        unsafe {
            let mut addr: addr_t = 0;

            if vmi_read_addr_va(self.vmi, vaddr, pid as _, &mut addr as *mut _)
                == status_VMI_FAILURE
            {
                bail!(
                    "Unable to read addr from address 0x{:X} for PID {}",
                    vaddr,
                    pid
                )
            } else {
                Ok(addr)
            }
        }
    }

    //vmi_read_8_va
    pub fn vmi_read_8_va(&self, vaddr: addr_t, pid: i32) -> Result<u8> {
        unsafe {
            let mut val: u8 = 0;

            if vmi_read_8_va(self.vmi, vaddr, pid as _, &mut val as *mut _) == status_VMI_FAILURE {
                bail!(
                    "Unable to read u8 from address 0x{:X} for PID {}",
                    vaddr,
                    pid
                )
            } else {
                Ok(val)
            }
        }
    }

    //vmi_read_16_va
    pub fn vmi_read_16_va(&self, vaddr: addr_t, pid: i32) -> Result<u16> {
        unsafe {
            let mut val: u16 = 0;

            if vmi_read_16_va(self.vmi, vaddr, pid as _, &mut val as *mut _) == status_VMI_FAILURE {
                bail!(
                    "Unable to read u16 from address 0x{:X} for PID {}",
                    vaddr,
                    pid
                )
            } else {
                Ok(val)
            }
        }
    }

    pub fn vmi_read_32_va(&self, vaddr: addr_t, pid: i32) -> Result<u32> {
        unsafe {
            let mut val: u32 = 0;

            if vmi_read_32_va(self.vmi, vaddr, pid as _, &mut val as *mut _) == status_VMI_FAILURE {
                bail!(
                    "Unable to read u32 from address 0x{:X} for PID {}",
                    vaddr,
                    pid
                )
            } else {
                Ok(val)
            }
        }
    }

    pub fn vmi_read_64_va(&self, vaddr: addr_t, pid: i32) -> Result<u64> {
        unsafe {
            let mut val: u64 = 0;

            if vmi_read_64_va(self.vmi, vaddr, pid as _, &mut val as *mut _) == status_VMI_FAILURE {
                bail!(
                    "Unable to read u64 from address 0x{:X} for PID {}",
                    vaddr,
                    pid
                )
            } else {
                Ok(val)
            }
        }
    }

    pub fn vmi_read_str_va(&self, vaddr: addr_t, pid: i32) -> Result<String> {
        unsafe {
            let s = vmi_read_str_va(self.vmi, vaddr, pid as _);

            if s.is_null() {
                bail!(format!(
                    "Unable to read string from address 0x{:X} for PID {}",
                    vaddr, pid
                ))
            } else {
                // Allocate a normal rust string
                let c_str = CStr::from_ptr(s).to_string_lossy().into_owned();

                // Free the one allocated by libvmi
                free(s as *mut _);

                Ok(c_str)
            }
        }
    }

    //pub fn vmi_read_unicode_str_va
    pub fn vmi_read_unicode_str_va(&self, vaddr: addr_t, pid: i32) -> Result<String> {
        unsafe {
            let us = vmi_read_unicode_str_va(self.vmi, vaddr, pid as _);
            if us.is_null() {
                bail!(format!(
                    "Unable to read string from address 0x{:X} for PID {}",
                    vaddr, pid
                ))
            } else {
                let mut out: unicode_string_t = unicode_string_t {
                    length: 0,
                    contents: std::ptr::null_mut(),
                    encoding: std::ptr::null_mut(),
                };

                let utf8 = CString::new("UTF-8")?;
                let status = vmi_convert_str_encoding(us, &mut out, utf8.as_ptr());

                vmi_free_unicode_str(us);
                let out_str = out.contents as *const i8;

                if !out_str.is_null() && status == status_VMI_SUCCESS {
                    let s = CStr::from_ptr(out_str).to_str()?.to_owned();
                    libc::free(out.contents as *mut _);
                    return Ok(s);
                }

                bail!("Unable to convert str encoding")
            }
        }
    }

    pub fn vmi_read_addr_ksym(&self, name: &str) -> Result<addr_t> {
        unsafe {
            let name = CString::new(name)?;
            let mut addr: addr_t = 0;
            if vmi_read_addr_ksym(self.vmi, name.as_ptr() as *mut _, &mut addr as *mut _)
                == status_VMI_FAILURE
            {
                bail!("Unable to read addr from symbol {:?}", name)
            } else {
                Ok(addr)
            }
        }
    }

    pub fn vmi_read_32_ksym(&self, name: &str) -> Result<u32> {
        unsafe {
            let name = CString::new(name)?;
            let mut val: u32 = 0;

            if vmi_read_32_ksym(self.vmi, name.as_ptr() as *mut _, &mut val as *mut _)
                == status_VMI_FAILURE
            {
                bail!("Unable to read u32 from symbol {:?}", name)
            } else {
                Ok(val)
            }
        }
    }

    pub fn vmi_read_64_ksym(&self, name: &str) -> Result<u64> {
        unsafe {
            let name = CString::new(name)?;
            let mut val: u64 = 0;

            if vmi_read_64_ksym(self.vmi, name.as_ptr() as *mut _, &mut val as *mut _)
                == status_VMI_FAILURE
            {
                bail!("Unable to read u64 from symbol {:?}", name)
            } else {
                Ok(val)
            }
        }
    }

    pub fn vmi_read_str_ksym(&self, name: &str) -> Result<String> {
        unsafe {
            let name = CString::new(name)?;
            let s = vmi_read_str_ksym(self.vmi, name.as_ptr() as *mut _);

            if s.is_null() {
                bail!("Unable to read string from symbol {:?}", name)
            } else {
                // Allocate a normal rust string
                let c_str = CStr::from_ptr(s).to_string_lossy().into_owned();

                // Free the one allocated by libvmi
                free(s as *mut _);

                Ok(c_str)
            }
        }
    }

    pub fn vmi_read_8_pa(&self, paddr: addr_t) -> Result<u8> {
        unsafe {
            let mut val: u8 = 0;

            if vmi_read_8_pa(self.vmi, paddr, &mut val as *mut _) == status_VMI_FAILURE {
                bail!("Unable to read u8 from physical address 0x{:X}", paddr)
            } else {
                Ok(val)
            }
        }
    }

    //vmi_read_16_pa
    pub fn vmi_read_16_pa(&self, paddr: addr_t) -> Result<u16> {
        unsafe {
            let mut val: u16 = 0;

            if vmi_read_16_pa(self.vmi, paddr, &mut val as *mut _) == status_VMI_FAILURE {
                bail!("Unable to read u16 from physical address 0x{:X}", paddr)
            } else {
                Ok(val)
            }
        }
    }

    //vmi_read_32_pa
    pub fn vmi_read_32_pa(&self, paddr: addr_t) -> Result<u32> {
        unsafe {
            let mut val: u32 = 0;

            if vmi_read_32_pa(self.vmi, paddr, &mut val as *mut _) == status_VMI_FAILURE {
                bail!("Unable to read u32 from physical address 0x{:X}", paddr)
            } else {
                Ok(val)
            }
        }
    }

    //vmi_read_64_pa
    pub fn vmi_read_64_pa(&self, paddr: addr_t) -> Result<u64> {
        unsafe {
            let mut val: u64 = 0;

            if vmi_read_64_pa(self.vmi, paddr, &mut val as *mut _) == status_VMI_FAILURE {
                bail!("Unable to read u64 from physical address 0x{:X}", paddr)
            } else {
                Ok(val)
            }
        }
    }

    //vmi_read_addr_pa
    pub fn vmi_read_addr_pa(&self, paddr: addr_t) -> Result<addr_t> {
        unsafe {
            let mut addr: addr_t = 0;

            if vmi_read_addr_pa(self.vmi, paddr, &mut addr as *mut _) == status_VMI_FAILURE {
                bail!("Unable to read addr from physical address 0x{:X}", paddr)
            } else {
                Ok(addr)
            }
        }
    }
    //vmi_read_str_pa
    pub fn vmi_read_str_pa(&self, paddr: addr_t) -> Result<String> {
        unsafe {
            let s = vmi_read_str_pa(self.vmi, paddr);
            if s.is_null() {
                bail!(format!(
                    "Unable to read string from physical address 0x{:X}",
                    paddr
                ))
            } else {
                // Allocate a normal rust string
                let c_str = CStr::from_ptr(s).to_string_lossy().into_owned();

                // Free the one allocated by libvmi
                free(s as *mut _);

                Ok(c_str)
            }
        }
    }
}

impl Drop for VmiInstance {
    fn drop(&mut self) {
        // Unpause the VM if it is paused
        if let Err(msg) = self.vmi_resume_vm() {
            eprintln!("Error while dropping VMI handle: {}", msg);
        }

        // Destroy the handle
        unsafe {
            if vmi_destroy(self.vmi) == status_VMI_FAILURE {
                eprintln!("Unable to destroy handle before dropping");
            }
        }
    }
}
