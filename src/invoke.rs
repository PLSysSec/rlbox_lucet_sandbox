use crate::types::{LucetSandboxInstance, LucetValue};

use lucet_runtime::{UntypedRetVal};
use lucet_runtime_internals::instance::InstanceInternal;

use std::ffi::{c_void, CStr};
use std::os::raw::{c_char, c_int};

#[no_mangle]
pub extern "C" fn lucet_lookup_function(
    inst_ptr: *mut c_void,
    fn_name: *const c_char,
) -> u32 {
    let inst = unsafe { &mut *(inst_ptr as *mut LucetSandboxInstance) };
    let name = unsafe { CStr::from_ptr(fn_name).to_string_lossy() };
    let func = inst
        .instance_handle
        .module()
        .get_export_func(&name)
        .unwrap();
    return func.id.as_u32();
}

#[no_mangle]
pub extern "C" fn lucet_run_function_return_void(
    inst_ptr: *mut c_void,
    fn_name: *const c_char,
    argc: c_int,
    argv: *mut LucetValue,
) {
    lucet_run_function_helper(inst_ptr, fn_name, argc, argv);
}

#[no_mangle]
pub extern "C" fn lucet_run_function_return_u32(
    inst_ptr: *mut c_void,
    fn_name: *const c_char,
    argc: c_int,
    argv: *mut LucetValue,
) -> u32 {
    let ret = lucet_run_function_helper(inst_ptr, fn_name, argc, argv);
    return ret.into();
}

#[no_mangle]
pub extern "C" fn lucet_run_function_return_u64(
    inst_ptr: *mut c_void,
    fn_name: *const c_char,
    argc: c_int,
    argv: *mut LucetValue,
) -> u64 {
    let ret = lucet_run_function_helper(inst_ptr, fn_name, argc, argv);
    return ret.into();
}

#[no_mangle]
pub extern "C" fn lucet_run_function_return_f32(
    inst_ptr: *mut c_void,
    fn_name: *const c_char,
    argc: c_int,
    argv: *mut LucetValue,
) -> f32 {
    let ret = lucet_run_function_helper(inst_ptr, fn_name, argc, argv);
    return ret.into();
}

#[no_mangle]
pub extern "C" fn lucet_run_function_return_f64(
    inst_ptr: *mut c_void,
    fn_name: *const c_char,
    argc: c_int,
    argv: *mut LucetValue,
) -> f64 {
    let ret = lucet_run_function_helper(inst_ptr, fn_name, argc, argv);
    return ret.into();
}


fn lucet_run_function_helper(
    inst_ptr: *mut c_void,
    fn_name: *const c_char,
    argc: c_int,
    argv: *mut LucetValue,
) -> UntypedRetVal {
    let inst = unsafe { &mut *(inst_ptr as *mut LucetSandboxInstance) };
    let name = unsafe { CStr::from_ptr(fn_name).to_string_lossy() };

    let args = if argc == 0 {
        vec![]
    } else {
        unsafe { std::slice::from_raw_parts(argv, argc as usize) }
            .into_iter()
            .map(|v| v.into())
            .collect()
    };

    let ret = inst.instance_handle.run(&name, &args);
    match &ret {
        Err(e) => {
            println!("Error {:?}!", e);
        }
        _ => {},
    };
    return ret.unwrap();
}