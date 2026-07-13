// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! No-hardware sanity check for the VPCI relay device policy.
//!
//! Run with:
//!
//! ```not_rust
//! cargo run -p vpci_relay --example gpu_policy
//! ```
//!
//! It authors a GPU-enabling policy that reproduces the short-term static allow
//! list (NVIDIA 3D controllers and NVIDIA NVSwitch bridges), authenticates it
//! through the measured-policy framework, and evaluates a set of synthetic
//! host-offered devices — so the admit/deny behavior can be verified without a
//! real GPU. It also exercises the two safety rails: a tampered blob fails
//! verification, and a policy outside the capability ceiling is rejected.

use measured_policy::MeasuredPolicyVerifier;
use measured_policy::load;
use measured_policy::measure;
use pci_core::spec::hwid::ClassCode;
use pci_core::spec::hwid::HardwareIds;
use pci_core::spec::hwid::ProgrammingInterface;
use pci_core::spec::hwid::Subclass;
use vpci_relay::DevicePolicy;

fn hw(vendor: u16, device: u16, base_class: u8, sub_class: u8) -> HardwareIds {
    HardwareIds {
        vendor_id: vendor,
        device_id: device,
        revision_id: 0,
        prog_if: ProgrammingInterface(0),
        sub_class: Subclass(sub_class),
        base_class: ClassCode(base_class),
        type0_sub_vendor_id: 0,
        type0_sub_system_id: 0,
    }
}

fn main() {
    // A GPU-enabling policy equivalent to today's short-term static entries.
    let policy_json = br#"{
        "version": 1,
        "rules": [
            { "vendor_id": 4318, "base_class": 3, "sub_class": 2 },
            { "vendor_id": 4318, "base_class": 6, "sub_class": 128 }
        ]
    }"#;

    // The platform measures the policy; the digest is what would be bound into
    // attestation. Authenticate and validate against the capability ceiling.
    let verifier = MeasuredPolicyVerifier::new(measure(policy_json));
    let policy: DevicePolicy = load(&verifier, policy_json).expect("policy should load");
    println!("loaded policy with {} rule(s)\n", policy.rules.len());

    // Evaluate synthetic host-offered devices (deny-by-default).
    let devices = [
        (
            "NVIDIA H100 (3D controller)",
            hw(0x10DE, 0x2330, 0x03, 0x02),
        ),
        ("NVIDIA NVSwitch (bridge)", hw(0x10DE, 0x22A3, 0x06, 0x80)),
        (
            "NVIDIA VGA (wrong subclass)",
            hw(0x10DE, 0x2330, 0x03, 0x00),
        ),
        (
            "Intel display (wrong vendor)",
            hw(0x8086, 0x2330, 0x03, 0x02),
        ),
    ];
    for (label, ids) in devices {
        let decision = if policy.admits(&ids) {
            "ADMIT"
        } else {
            "DENY "
        };
        println!("  [{decision}] {label}");
    }

    // Rail A: the host cannot substitute a different policy.
    let tampered = br#"{"version":1,"rules":[{"vendor_id":4318,"base_class":6,"sub_class":128}]}"#;
    assert!(load::<DevicePolicy>(&verifier, tampered).is_err());
    println!("\ntampered blob rejected: verification failed");

    // Rail B: a policy outside the ceiling is rejected even if measured.
    let out_of_ceiling = br#"{"version":1,"rules":[{"vendor_id":32902,"base_class":3}]}"#;
    let v = MeasuredPolicyVerifier::new(measure(out_of_ceiling));
    assert!(load::<DevicePolicy>(&v, out_of_ceiling).is_err());
    println!("out-of-ceiling policy rejected at load");
}
