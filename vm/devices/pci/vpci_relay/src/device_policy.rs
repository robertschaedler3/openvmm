// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device-admission policy for the VPCI relay.
//!
//! Implements the [`measured_policy`] framework for the "which host devices may
//! be relayed into a confidential guest" domain. A [`DevicePolicy`] extends the
//! relay's static allow list with additional admissions, bounded by a
//! compiled-in capability ceiling that a policy may narrow but never widen.

use measured_policy::MeasuredPolicy;
use pci_core::spec::hwid::HardwareIds;
use serde::Deserialize;
use serde::Serialize;

const NVIDIA_VENDOR_ID: u16 = 0x10DE;
const CLASS_DISPLAY_CONTROLLER: u8 = 0x03;
const CLASS_BRIDGE: u8 = 0x06;

/// The policy schema version understood by this build.
pub const SCHEMA_VERSION: u32 = 1;

/// An inclusive device-ID range. A `None` bound is open on that end, so a rule
/// can cover a whole GPU family and future SKUs within it.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdRange {
    /// Inclusive lower bound, or `None` for open-below.
    #[serde(default)]
    pub start: Option<u16>,
    /// Inclusive upper bound, or `None` for open-above.
    #[serde(default)]
    pub end: Option<u16>,
}

impl DeviceIdRange {
    /// Matches any device ID.
    pub const ANY: Self = Self {
        start: None,
        end: None,
    };

    /// Matches a single device ID.
    pub const fn exact(id: u16) -> Self {
        Self {
            start: Some(id),
            end: Some(id),
        }
    }

    /// An inclusive `start..=end` range.
    pub const fn inclusive(start: u16, end: u16) -> Self {
        Self {
            start: Some(start),
            end: Some(end),
        }
    }

    /// Whether `id` falls within the range.
    pub fn contains(&self, id: u16) -> bool {
        self.start.is_none_or(|s| id >= s) && self.end.is_none_or(|e| id <= e)
    }

    /// Whether every ID in `self` is also in `other`.
    fn is_subset_of(&self, other: &DeviceIdRange) -> bool {
        let lower = match (self.start, other.start) {
            (_, None) => true,
            (Some(s), Some(o)) => s >= o,
            (None, Some(_)) => false,
        };
        let upper = match (self.end, other.end) {
            (_, None) => true,
            (Some(s), Some(o)) => s <= o,
            (None, Some(_)) => false,
        };
        lower && upper
    }
}

/// A single device-admission rule. Every populated field must match; `None`
/// fields are wildcards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// PCI vendor ID.
    #[serde(default)]
    pub vendor_id: Option<u16>,
    /// PCI device ID range.
    #[serde(default)]
    pub device_id: Option<DeviceIdRange>,
    /// PCI revision ID.
    #[serde(default)]
    pub revision_id: Option<u8>,
    /// PCI programming interface.
    #[serde(default)]
    pub prog_if: Option<u8>,
    /// PCI subclass.
    #[serde(default)]
    pub sub_class: Option<u8>,
    /// PCI base class.
    #[serde(default)]
    pub base_class: Option<u8>,
    /// PCI subsystem vendor ID.
    #[serde(default)]
    pub sub_vendor_id: Option<u16>,
    /// PCI subsystem ID.
    #[serde(default)]
    pub sub_system_id: Option<u16>,
}

impl PolicyRule {
    /// Whether this rule admits the device described by `hw`.
    pub fn matches(&self, hw: &HardwareIds) -> bool {
        self.vendor_id.is_none_or(|v| v == hw.vendor_id)
            && self.device_id.is_none_or(|r| r.contains(hw.device_id))
            && self.revision_id.is_none_or(|v| v == hw.revision_id)
            && self.prog_if.is_none_or(|v| v == hw.prog_if.0)
            && self.sub_class.is_none_or(|v| v == hw.sub_class.0)
            && self.base_class.is_none_or(|v| v == hw.base_class.0)
            && self
                .sub_vendor_id
                .is_none_or(|v| v == hw.type0_sub_vendor_id)
            && self
                .sub_system_id
                .is_none_or(|v| v == hw.type0_sub_system_id)
    }
}

/// A versioned device-admission policy. Load it through the [`measured_policy`]
/// framework (`measured_policy::load::<DevicePolicy>`) so it is authenticated
/// and validated against the capability ceiling before use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePolicy {
    /// Schema version; must equal [`SCHEMA_VERSION`].
    pub version: u32,
    /// Admission rules. Deny-by-default: a device is admitted only if a rule
    /// matches.
    pub rules: Vec<PolicyRule>,
}

impl DevicePolicy {
    /// Whether the policy admits the device described by `hw`.
    pub fn admits(&self, hw: &HardwareIds) -> bool {
        self.rules.iter().any(|r| r.matches(hw))
    }
}

/// Parse and validate a device policy from raw (already-delivered) bytes,
/// enforcing the capability ceiling.
///
/// This performs the structural checks (schema, version, ceiling) but not
/// authenticity. Callers that must authenticate the bytes should instead use
/// the [`measured_policy`] framework's `load` with a `PolicyVerifier`.
pub fn load_from_bytes(bytes: &[u8]) -> Result<DevicePolicy, DevicePolicyError> {
    let policy = DevicePolicy::parse(bytes)?;
    policy.validate()?;
    Ok(policy)
}

/// An error parsing or validating a [`DevicePolicy`].
#[derive(Debug, thiserror::Error)]
pub enum DevicePolicyError {
    /// The bytes were not valid policy JSON.
    #[error("failed to parse device policy: {0}")]
    Parse(String),
    /// The schema version is not understood by this build.
    #[error("unsupported device policy version {0} (expected {SCHEMA_VERSION})")]
    UnsupportedVersion(u32),
    /// A rule would admit a device outside the compiled-in capability ceiling.
    #[error("device policy rule {0} exceeds the capability ceiling")]
    RuleExceedsCeiling(usize),
}

impl MeasuredPolicy for DevicePolicy {
    const DOMAIN: &'static str = "vpci-device";
    type Error = DevicePolicyError;

    fn parse(bytes: &[u8]) -> Result<Self, DevicePolicyError> {
        serde_json::from_slice(bytes).map_err(|e| DevicePolicyError::Parse(e.to_string()))
    }

    fn validate(&self) -> Result<(), DevicePolicyError> {
        if self.version != SCHEMA_VERSION {
            return Err(DevicePolicyError::UnsupportedVersion(self.version));
        }
        for (index, rule) in self.rules.iter().enumerate() {
            if !CAPABILITY_CEILING.iter().any(|c| c.admits_rule(rule)) {
                return Err(DevicePolicyError::RuleExceedsCeiling(index));
            }
        }
        Ok(())
    }
}

/// One entry in the compiled-in capability ceiling.
struct CeilingEntry {
    vendor_id: Option<u16>,
    device_id: DeviceIdRange,
    base_class: Option<u8>,
    sub_class: Option<u8>,
}

impl CeilingEntry {
    /// Whether every device `rule` could admit is also admitted by this entry.
    fn admits_rule(&self, rule: &PolicyRule) -> bool {
        self.vendor_id.is_none_or(|v| rule.vendor_id == Some(v))
            && self.base_class.is_none_or(|c| rule.base_class == Some(c))
            && self.sub_class.is_none_or(|c| rule.sub_class == Some(c))
            && rule
                .device_id
                .unwrap_or(DeviceIdRange::ANY)
                .is_subset_of(&self.device_id)
    }
}

/// The compiled-in upper bound on what any policy may admit: NVIDIA display
/// controllers (GPUs) and NVIDIA bridges (NVSwitch NVLink fabric). Extending
/// this to a new device class is a reviewed source change, not a policy change.
static CAPABILITY_CEILING: &[CeilingEntry] = &[
    CeilingEntry {
        vendor_id: Some(NVIDIA_VENDOR_ID),
        device_id: DeviceIdRange::ANY,
        base_class: Some(CLASS_DISPLAY_CONTROLLER),
        sub_class: None,
    },
    CeilingEntry {
        vendor_id: Some(NVIDIA_VENDOR_ID),
        device_id: DeviceIdRange::ANY,
        base_class: Some(CLASS_BRIDGE),
        sub_class: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use measured_policy::MeasuredPolicyVerifier;
    use measured_policy::load;
    use pci_core::spec::hwid::ClassCode;
    use pci_core::spec::hwid::ProgrammingInterface;
    use pci_core::spec::hwid::Subclass;

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

    // Reproduces the short-term static GPU allow list: NVIDIA 3D controllers and
    // NVIDIA NVSwitch bridges.
    fn gpu_policy_json() -> &'static str {
        r#"{
            "version": 1,
            "rules": [
                { "vendor_id": 4318, "base_class": 3, "sub_class": 2 },
                { "vendor_id": 4318, "base_class": 6, "sub_class": 128 }
            ]
        }"#
    }

    fn parse(json: &str) -> Result<DevicePolicy, DevicePolicyError> {
        let policy = DevicePolicy::parse(json.as_bytes())?;
        policy.validate()?;
        Ok(policy)
    }

    #[test]
    fn device_id_range_contains() {
        let r = DeviceIdRange::inclusive(0x2330, 0x2BFF);
        assert!(r.contains(0x2330));
        assert!(r.contains(0x2BFF));
        assert!(!r.contains(0x232F));
        assert!(!r.contains(0x2C00));
        assert!(DeviceIdRange::ANY.contains(u16::MAX));
        assert!(DeviceIdRange::exact(5).contains(5));
        assert!(!DeviceIdRange::exact(5).contains(6));
    }

    #[test]
    fn device_id_range_subset() {
        let bounded = DeviceIdRange::inclusive(10, 20);
        assert!(DeviceIdRange::inclusive(12, 18).is_subset_of(&bounded));
        assert!(DeviceIdRange::exact(10).is_subset_of(&bounded));
        assert!(!DeviceIdRange::inclusive(9, 18).is_subset_of(&bounded));
        assert!(!DeviceIdRange::inclusive(12, 21).is_subset_of(&bounded));
        assert!(!DeviceIdRange::ANY.is_subset_of(&bounded));
        assert!(DeviceIdRange::ANY.is_subset_of(&DeviceIdRange::ANY));
    }

    #[test]
    fn deny_by_default() {
        let policy = DevicePolicy {
            version: 1,
            rules: Vec::new(),
        };
        assert!(!policy.admits(&hw(NVIDIA_VENDOR_ID, 0x2330, 0x03, 0x02)));
    }

    #[test]
    fn admits_gpu_and_bridge_but_not_others() {
        let policy = parse(gpu_policy_json()).unwrap();
        assert!(policy.admits(&hw(NVIDIA_VENDOR_ID, 0x2330, 0x03, 0x02))); // H100
        assert!(policy.admits(&hw(NVIDIA_VENDOR_ID, 0x22A3, 0x06, 0x80))); // NVSwitch
        assert!(!policy.admits(&hw(NVIDIA_VENDOR_ID, 0x2330, 0x03, 0x00))); // VGA subclass
        assert!(!policy.admits(&hw(0x8086, 0x2330, 0x03, 0x02))); // wrong vendor
    }

    // The policy admits exactly the devices the short-term static entries did.
    #[test]
    fn parity_with_short_term_static_list() {
        let policy = parse(gpu_policy_json()).unwrap();
        // The short-term entries: (vendor 0x10DE, base 0x03, sub 0x02) and
        // (vendor 0x10DE, base 0x06, sub 0x80).
        let short_term = |hw: &HardwareIds| {
            (hw.vendor_id == 0x10DE && hw.base_class.0 == 0x03 && hw.sub_class.0 == 0x02)
                || (hw.vendor_id == 0x10DE && hw.base_class.0 == 0x06 && hw.sub_class.0 == 0x80)
        };
        for &(vendor, device, base, sub) in &[
            (0x10DE, 0x2330, 0x03, 0x02),
            (0x10DE, 0x22A3, 0x06, 0x80),
            (0x10DE, 0x2330, 0x03, 0x00),
            (0x10DE, 0x1234, 0x02, 0x00),
            (0x8086, 0x2330, 0x03, 0x02),
            (0x10DE, 0x0000, 0x06, 0x04),
        ] {
            let ids = hw(vendor, device, base, sub);
            assert_eq!(policy.admits(&ids), short_term(&ids), "{ids:x?}");
        }
    }

    #[test]
    fn ceiling_rejects_foreign_vendor() {
        let json = r#"{"version":1,"rules":[{"vendor_id":32902,"base_class":3}]}"#;
        assert!(matches!(
            parse(json),
            Err(DevicePolicyError::RuleExceedsCeiling(0))
        ));
    }

    #[test]
    fn ceiling_rejects_foreign_class() {
        let json = r#"{"version":1,"rules":[{"vendor_id":4318,"base_class":1}]}"#;
        assert!(matches!(
            parse(json),
            Err(DevicePolicyError::RuleExceedsCeiling(0))
        ));
    }

    #[test]
    fn ceiling_rejects_unpinned_vendor() {
        let json = r#"{"version":1,"rules":[{"base_class":3}]}"#;
        assert!(matches!(
            parse(json),
            Err(DevicePolicyError::RuleExceedsCeiling(0))
        ));
    }

    #[test]
    fn unsupported_version_rejected() {
        let json = r#"{"version":2,"rules":[]}"#;
        assert!(matches!(
            parse(json),
            Err(DevicePolicyError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn malformed_json_does_not_panic() {
        assert!(matches!(
            DevicePolicy::parse(b"not json"),
            Err(DevicePolicyError::Parse(_))
        ));
        assert!(matches!(
            DevicePolicy::parse(b""),
            Err(DevicePolicyError::Parse(_))
        ));
    }

    #[test]
    fn loads_through_framework() {
        let blob = gpu_policy_json().as_bytes();
        let verifier = MeasuredPolicyVerifier::new(measured_policy::measure(blob));
        let policy: DevicePolicy = load(&verifier, blob).unwrap();
        assert_eq!(policy.rules.len(), 2);
    }

    #[test]
    fn framework_rejects_tampered_policy() {
        let blob = gpu_policy_json().as_bytes();
        let verifier = MeasuredPolicyVerifier::new(measured_policy::measure(blob));
        let other = r#"{"version":1,"rules":[{"vendor_id":4318,"base_class":6,"sub_class":128}]}"#;
        assert!(load::<DevicePolicy>(&verifier, other.as_bytes()).is_err());
    }
}
