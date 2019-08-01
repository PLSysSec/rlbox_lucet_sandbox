use crate::types::LucetSandboxInstance;

use std::ffi::c_void;

#[no_mangle]
pub extern "C" fn lucet_get_heap_base(inst_ptr: *mut c_void) -> *mut c_void {
    let inst = unsafe { &mut *(inst_ptr as *mut LucetSandboxInstance) };
    let heap_view = inst.instance_handle.heap_mut();
    let heap_base = heap_view.as_mut_ptr() as *mut c_void;
    return heap_base;
}

#[no_mangle]
pub extern "C" fn lucet_get_heap_size(inst_ptr: *mut c_void) -> usize {
    let inst = unsafe { &mut *(inst_ptr as *mut LucetSandboxInstance) };
    let heap_view = inst.instance_handle.heap_mut();
    return heap_view.len();
}

#[no_mangle]
pub extern "C" fn lucet_get_unsandboxed_ptr(
    inst_ptr: *mut c_void,
    sandboxed_ptr: usize,
) -> *mut c_void {
    let inst = unsafe { &mut *(inst_ptr as *mut LucetSandboxInstance) };

    let heap_view = inst.instance_handle.heap_mut();
    assert!(sandboxed_ptr <= heap_view.len());
    let ptr_ref = &mut heap_view[sandboxed_ptr];
    return ptr_ref as *mut u8 as *mut c_void;
}

#[no_mangle]
pub extern "C" fn lucet_get_sandboxed_ptr(
    inst_ptr: *mut c_void,
    unsandboxed_ptr: *mut c_void,
) -> usize {
    let inst = unsafe { &mut *(inst_ptr as *mut LucetSandboxInstance) };

    let heap_view = inst.instance_handle.heap_mut();
    let heap_base = heap_view[0] as *mut u8 as *mut c_void;
    let heap_top = heap_view[heap_view.len() - 1] as *mut u8 as *mut c_void;
    assert!(unsandboxed_ptr >= heap_base && unsandboxed_ptr <= heap_top);
    return (unsandboxed_ptr as usize) - (heap_base as usize);
}
