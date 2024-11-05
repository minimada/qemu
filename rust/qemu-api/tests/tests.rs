// Copyright 2024, Linaro Limited
// Author(s): Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::CStr;

use qemu_api::{
    bindings::*,
    c_str,
    cell::{self, BqlCell},
    declare_properties, define_property,
    prelude::*,
    qdev::{DeviceImpl, DeviceState, Property},
    qom::ObjectImpl,
    vmstate::VMStateDescription,
    zeroable::Zeroable,
};

// Test that macros can compile.
pub static VMSTATE: VMStateDescription = VMStateDescription {
    name: c_str!("name").as_ptr(),
    unmigratable: true,
    ..Zeroable::ZERO
};

#[derive(qemu_api_macros::offsets)]
#[repr(C)]
#[derive(qemu_api_macros::Object)]
pub struct DummyState {
    parent: DeviceState,
    migrate_clock: bool,
}

declare_properties! {
    DUMMY_PROPERTIES,
        define_property!(
            c_str!("migrate-clk"),
            DummyState,
            migrate_clock,
            unsafe { &qdev_prop_bool },
            bool
        ),
}

unsafe impl ObjectType for DummyState {
    type Class = <DeviceState as ObjectType>::Class;
    const TYPE_NAME: &'static CStr = c_str!("dummy");
}

impl ObjectImpl for DummyState {
    type ParentType = DeviceState;
    const ABSTRACT: bool = false;
}

impl DeviceImpl for DummyState {
    fn properties() -> &'static [Property] {
        &DUMMY_PROPERTIES
    }
    fn vmsd() -> Option<&'static VMStateDescription> {
        Some(&VMSTATE)
    }
}

fn init_qom() {
    static ONCE: BqlCell<bool> = BqlCell::new(false);

    cell::bql_start_test();
    if !ONCE.get() {
        unsafe {
            module_call_init(module_init_type::MODULE_INIT_QOM);
        }
        ONCE.set(true);
    }
}

#[test]
/// Create and immediately drop an instance.
fn test_object_new() {
    init_qom();
    unsafe {
        object_unref(object_new(DummyState::TYPE_NAME.as_ptr()).cast());
    }
}
