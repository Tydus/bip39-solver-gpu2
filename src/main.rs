use std::fs;
use std::ffi::{CString};
use ocl::{core, flags};
use ocl::prm::{cl_ulong};
use ocl::enums::ArgVal;
use ocl::builders::ContextProperties;
use std::str;
use std::time::Instant;
//use rand::Rng;
use rand::prelude::*;
use rand::prng::hc128::Hc128Rng;

use rayon::prelude::*;
use serde::{Deserialize};

#[derive(Deserialize, Debug)]
struct WorkResponse {
  indices: Vec<u128>,
  offset: u128,
  batch_size: u64
}

fn mnemonic_gpu(platform_id: core::types::abs::PlatformId, device_id: core::types::abs::DeviceId, src: std::ffi::CString, kernel_name: &String) -> ocl::core::Result<()> {
  let context_properties = ContextProperties::new().platform(platform_id);
  let context = core::create_context(Some(&context_properties), &[device_id], None, None).unwrap();
  let program = core::create_program_with_source(&context, &[src]).unwrap();
  core::build_program(&program, Some(&[device_id]), &CString::new("").unwrap(), None, None).unwrap();
  let queue = core::create_command_queue(&context, &device_id, None).unwrap();
  //let mut rng = rand::thread_rng();
  let mut rng = Hc128Rng::from_entropy();

  loop {
    let now = Instant::now();


    let start_0: cl_ulong = rng.gen();
    let start_1: cl_ulong = rng.gen();
    let start_2: cl_ulong = rng.gen();
    let start_3: cl_ulong = rng.gen();
    //println!("start={:#016x} {:#016x} {:#016x} {:#016x}", start_3, start_2, start_1, start_0);

    let items: u64 = 1048576;

    let mut target_mnemonic = vec![0u8; 360];
    let mut mnemonic_found = vec![0u8; 1];
    
    let target_mnemonic_buf = unsafe { core::create_buffer(&context, flags::MEM_WRITE_ONLY |
      flags::MEM_COPY_HOST_PTR, 360, Some(&target_mnemonic))? };
    
    let mnemonic_found_buf = unsafe { core::create_buffer(&context, flags::MEM_WRITE_ONLY |
        flags::MEM_COPY_HOST_PTR, 1, Some(&mnemonic_found))? };
  
    let kernel = core::create_kernel(&program, kernel_name)?;

    core::set_kernel_arg(&kernel, 0, ArgVal::scalar(&start_3))?;
    core::set_kernel_arg(&kernel, 1, ArgVal::scalar(&start_2))?;
    core::set_kernel_arg(&kernel, 2, ArgVal::scalar(&start_1))?;
    core::set_kernel_arg(&kernel, 3, ArgVal::scalar(&start_0))?;
    core::set_kernel_arg(&kernel, 4, ArgVal::mem(&target_mnemonic_buf))?;
    core::set_kernel_arg(&kernel, 5, ArgVal::mem(&mnemonic_found_buf))?;

    unsafe { core::enqueue_kernel(&queue, &kernel, 1, None, &[items as usize,1,1],
        None, None::<core::Event>, None::<&mut core::Event>)?; }
    
    unsafe { core::enqueue_read_buffer(&queue, &target_mnemonic_buf, true, 0, &mut target_mnemonic,
        None::<core::Event>, None::<&mut core::Event>)?; }

    
    unsafe { core::enqueue_read_buffer(&queue, &mnemonic_found_buf, true, 0, &mut mnemonic_found,
        None::<core::Event>, None::<&mut core::Event>)?; }
    
    if mnemonic_found[0] == 0x01 {
      let s = match String::from_utf8((&target_mnemonic[0..360]).to_vec()) {
          Ok(v) => v,
          Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
      };
      let mnemonic = s.trim_matches(char::from(0));
      println!("mnemonic={}", mnemonic.to_string());

    }

    println!("{} Keys / s", 1000. * items as f64 / now.elapsed().as_millis() as f64);

  }
}


fn main() {
  let platform_id = core::default_platform().unwrap();
  let device_ids = core::get_device_ids(&platform_id, Some(ocl::flags::DEVICE_TYPE_GPU), None).unwrap();

  let int_to_address_kernel: String = "int_to_address".to_string();
  let int_to_address_files = ["common", "ripemd", "sha2", "secp256k1_common", "secp256k1_scalar", "secp256k1_field", "secp256k1_group", "secp256k1_prec", "secp256k1", "address", "mnemonic_constants", "int_to_address"];

  let files = int_to_address_files;
  let kernel_name = int_to_address_kernel;

  let mut raw_cl_file = "".to_string();

  for file in &files {
    let file_path = format!("./cl/{}.cl", file);
    let file_str = fs::read_to_string(file_path).unwrap();
    raw_cl_file.push_str(&file_str);
    raw_cl_file.push_str("\n");
  }

  let src_cstring = CString::new(raw_cl_file).unwrap();
  
  device_ids.into_par_iter().for_each(move |device_id| mnemonic_gpu(platform_id, device_id, src_cstring.clone(), &kernel_name).unwrap());
}
