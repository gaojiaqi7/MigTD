// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::{TryFrom, TryInto};

use alloc::{collections::btree_map::BTreeMap, format, string::String, vec::Vec};
use ring::{
    rand,
    signature::{
        EcdsaKeyPair, UnparsedPublicKey, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{parse_events, CcEvent, EventName, MigTdInfoProperty, PolicyError, Report};

pub mod collateral;

#[derive(Debug)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

impl TcbStatus {
    pub fn as_str(&self) -> &str {
        match self {
            TcbStatus::UpToDate => "UpToDate",
            TcbStatus::SWHardeningNeeded => "SWHardeningNeeded",
            TcbStatus::ConfigurationNeeded => "ConfigurationNeeded",
            TcbStatus::ConfigurationAndSWHardeningNeeded => "ConfigurationAndSWHardeningNeeded",
            TcbStatus::OutOfDate => "OutOfDate",
            TcbStatus::OutOfDateConfigurationNeeded => "OutOfDateConfigurationNeeded",
            TcbStatus::Revoked => "Revoked",
        }
    }
}

impl TryFrom<&str> for TcbStatus {
    type Error = PolicyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "UpToDate" => Ok(TcbStatus::UpToDate),
            "SWHardeningNeeded" => Ok(TcbStatus::SWHardeningNeeded),
            "ConfigurationNeeded" => Ok(TcbStatus::ConfigurationNeeded),
            "ConfigurationAndSWHardeningNeeded" => Ok(TcbStatus::ConfigurationAndSWHardeningNeeded),
            "OutOfDate" => Ok(TcbStatus::OutOfDate),
            "OutOfDateConfigurationNeeded" => Ok(TcbStatus::OutOfDateConfigurationNeeded),
            "Revoked" => Ok(TcbStatus::Revoked),
            _ => Err(PolicyError::InvalidParameter),
        }
    }
}

/// Contains all required data to verify a policy
#[derive(Debug, Clone)]
pub struct PolicyEvaluationInfo {
    /// The date of the Trusted Computing Base (TCB) in ISO-8601 format, e.g. "2023-06-19T00:00:00Z"
    pub tcb_date: Option<String>,

    /// The status of the TCB
    pub tcb_status: Option<String>,

    /// The TCB evaluation data number used to track TCB revocations and updates
    pub tcb_evaluation_number: Option<u32>,

    /// The engine SVN
    pub engine_svn: Option<u32>,
}

pub fn verify_policy_signature<'a>(
    policy: &'a [u8],
    public_key: &[u8],
) -> Result<PartialMigPolicy<'a>, PolicyError> {
    let partial_mig_policy = PartialMigPolicy::deserialize_from_json(policy)?;

    let signature_bytes = hex_string_to_bytes(
        partial_mig_policy
            .signature
            .as_ref()
            .ok_or(PolicyError::SignatureVerificationFailed)?,
    )?;
    verify_ecdsa_384_signature(
        partial_mig_policy.policy.get().as_bytes(),
        &signature_bytes,
        public_key,
    )?;

    Ok(partial_mig_policy)
}

pub fn verify_policy_integrity(
    policy: &[u8],
    public_key: &[u8],
    event_log: &[u8],
) -> Result<MigPolicy, PolicyError> {
    let partial_mig_policy = verify_policy_signature(policy, public_key)?;
    let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;

    if !verify_event_hash(
        &events,
        &EventName::MigTdEngine,
        partial_mig_policy.policy.get().as_bytes(),
    )? {
        return Err(PolicyError::InvalidEngineSvnMap);
    }
    partial_mig_policy.try_into()
}

pub fn verify_engine_signature<'a>(
    engine: &'a [u8],
    public_key: &[u8],
) -> Result<PartialEngineSvnMap<'a>, PolicyError> {
    let partial_engine_svn_map = PartialEngineSvnMap::deserialize_from_json(engine)?;

    let signature_bytes = hex_string_to_bytes(
        &partial_engine_svn_map
            .signature
            .as_ref()
            .ok_or(PolicyError::SignatureVerificationFailed)?,
    )?;
    verify_ecdsa_384_signature(
        partial_engine_svn_map.engine_svn.get().as_bytes(),
        &signature_bytes,
        public_key,
    )?;

    Ok(partial_engine_svn_map)
}

pub fn verify_engine_integrity(
    engine: &[u8],
    public_key: &[u8],
    event_log: &[u8],
) -> Result<EngineSvnMap, PolicyError> {
    let partial_engine_svn_map = verify_engine_signature(engine, public_key)?;
    let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;

    if !verify_event_hash(
        &events,
        &EventName::MigTdEngine,
        partial_engine_svn_map.engine_svn.get().as_bytes(),
    )? {
        return Err(PolicyError::InvalidEngineSvnMap);
    }
    partial_engine_svn_map.try_into()
}

// Verify the hash of a specific event in the event log
fn verify_event_hash(
    events: &BTreeMap<EventName, CcEvent>,
    event_name: &EventName,
    data_to_hash: &[u8],
) -> Result<bool, PolicyError> {
    let event = match events.get(event_name) {
        Some(event) => event,
        None => return Ok(false), // Event not found
    };

    let event_digest = &event
        .header
        .digest
        .digests
        .first()
        .ok_or(PolicyError::InvalidEventLog)?
        .digest
        .sha384;

    let expected_hash = get_sha384_hash(data_to_hash).map_err(|_| PolicyError::HashCalculation)?;

    // Compare the calculated digest with the expected digest
    Ok(&expected_hash == event_digest)
}

pub fn get_engine_svn_from_map(engine: &[u8], report: &[u8]) -> Result<u32, PolicyError> {
    let engine_svn_map = parse_engine_svn_map(engine)?;
    let report_values = Report::new(report)?;

    engine_svn_map
        .get_engine_svn(&report_values)
        .ok_or(PolicyError::SvnMismatch)
}

fn parse_engine_svn_map(engine: &[u8]) -> Result<EngineSvnMap, PolicyError> {
    // Remove the trailing zeros
    let engine_str = core::str::from_utf8(engine)
        .map(|s| s.trim_matches(char::from(0)))
        .map_err(|_| PolicyError::InvalidPolicy)?;
    serde_json::from_str::<EngineSvnMap>(engine_str).map_err(|_| PolicyError::InvalidPolicy)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialMigPolicy<'a> {
    #[serde(borrow)]
    policy: &'a RawValue,
    signature: Option<String>,
}

impl<'a> PartialMigPolicy<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<PartialMigPolicy>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), PolicyError> {
        let signature = ecdsa_p384_sign(self.policy.get().as_bytes(), signing_key)?;
        self.signature = Some(bytes_to_hex_string(&signature));

        Ok(())
    }
}

impl TryInto<MigPolicy> for PartialMigPolicy<'_> {
    type Error = PolicyError;
    fn try_into(self) -> Result<MigPolicy, Self::Error> {
        let policy =
            serde_json::from_str(self.policy.get()).map_err(|_| PolicyError::InvalidPolicy)?;
        Ok(MigPolicy {
            policy,
            signature: self.signature.ok_or(PolicyError::InvalidPolicy)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigPolicy {
    policy: Policy,
    signature: String,
}

impl MigPolicy {
    pub fn deserialize_from_json(json: &[u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<MigPolicy>(json).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn validate(&self) -> bool {
        if self.policy.id.is_empty() || self.policy.version.is_empty() {
            return false;
        }

        self.policy
            .common_policy
            .as_ref()
            .is_none_or(|common| MigPolicy::validate_policy_block(&common, PolicyBlockType::Common))
            && self.policy.forward_policy.as_ref().is_none_or(|forward| {
                MigPolicy::validate_policy_block(&forward, PolicyBlockType::Forward)
            })
            && self.policy.backward_policy.as_ref().is_none_or(|backward| {
                MigPolicy::validate_policy_block(&backward, PolicyBlockType::Backward)
            })
    }

    fn validate_policy_block(block: &Vec<PolicyTypes>, block_type: PolicyBlockType) -> bool {
        for policy_type in block {
            match policy_type {
                PolicyTypes::Global(global) => {
                    if !global
                        .tcb_number
                        .tcb_date
                        .as_ref()
                        .is_none_or(|p| p.validate(block_type))
                    {
                        return false;
                    }
                }
                PolicyTypes::MigTD(migtd) => {
                    if !migtd.migtd_identity.svn.validate(PolicyBlockType::Common) {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn evaluate_policy_forward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.policy.forward_policy.as_ref() {
            Some(policy) => MigPolicy::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_backward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.policy.backward_policy.as_ref() {
            Some(policy) => MigPolicy::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_common(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        match self.policy.common_policy.as_ref() {
            Some(policy) => MigPolicy::evaluate_policy_block(policy, value, relative_reference),
            None => Ok(()),
        }
    }

    fn evaluate_policy_block(
        block: &Vec<PolicyTypes>,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        for policy_type in block {
            match policy_type {
                PolicyTypes::Global(global) => global.evaluate(value, relative_reference)?,
                PolicyTypes::MigTD(migtd) => migtd.evaluate(value, relative_reference)?,
            }
        }
        Ok(())
    }

    /// Evaluate another MigPolicy against this policy
    ///
    /// # Arguments
    /// * `other_policy` - The policy to evaluate against this one
    ///
    /// # Returns
    /// * `Ok(())` if all evaluations pass
    /// * `Err(PolicyError)` if evaluation fails or required policy blocks are missing
    pub fn evaluate_against_policy(
        &self,
        other_policy: &MigPolicy,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        // Check if required policy blocks exist in both policies
        if self.policy.common_policy.is_some() && other_policy.policy.common_policy.is_none() {
            return Err(PolicyError::InvalidPolicy);
        }
        if self.policy.forward_policy.is_some() && other_policy.policy.forward_policy.is_none() {
            return Err(PolicyError::InvalidPolicy);
        }
        if self.policy.backward_policy.is_some() && other_policy.policy.backward_policy.is_none() {
            return Err(PolicyError::InvalidPolicy);
        }

        // Evaluate common policy if it exists
        if let Some(_) = &self.policy.common_policy {
            let other_eval_info =
                Self::extract_policy_evaluation_info(other_policy, PolicyBlockType::Common);
            self.evaluate_policy_common(&other_eval_info, relative_reference)?;
        }

        // Evaluate forward policy if it exists
        if let Some(_) = &self.policy.forward_policy {
            let other_eval_info =
                Self::extract_policy_evaluation_info(other_policy, PolicyBlockType::Forward);
            self.evaluate_policy_forward(&other_eval_info, relative_reference)?;
        }

        // Evaluate backward policy if it exists
        if let Some(_) = &self.policy.backward_policy {
            let other_eval_info =
                Self::extract_policy_evaluation_info(other_policy, PolicyBlockType::Backward);
            self.evaluate_policy_backward(&other_eval_info, relative_reference)?;
        }

        Ok(())
    }

    /// Extract PolicyEvaluationInfo from a MigPolicy
    fn extract_policy_evaluation_info(
        policy: &MigPolicy,
        block_type: PolicyBlockType,
    ) -> PolicyEvaluationInfo {
        let mut tcb_date = None;
        let mut tcb_status = None;
        let mut tcb_evaluation_number = None;
        let mut engine_svn = None;

        // Helper function to extract values from a policy block
        let extract_from_block =
            |block: &Vec<PolicyTypes>| -> (Option<String>, Option<u32>, Option<u32>) {
                let mut date = None;
                // let mut status = None;
                let mut eval_num = None;
                let mut svn = None;

                for policy_type in block {
                    match policy_type {
                        PolicyTypes::Global(global) => {
                            // Extract TCB information from GlobalPolicy
                            if let Some(ref tcb_date_prop) = global.tcb_number.tcb_date {
                                if let Reference::String(val) = &tcb_date_prop.reference {
                                    date = Some(val.clone());
                                }
                            }
                            if let Some(ref tcb_eval_prop) =
                                global.tcb_number.tcb_evaluation_data_number
                            {
                                if let Reference::Integer(val) = &tcb_eval_prop.reference {
                                    eval_num = Some(*val);
                                }
                            }
                            // // For tcb_status, if it's a string list, we might need special handling
                            // if let Some(ref tcb_status_prop) = global.tcb_number.tcb_status {
                            //     // This is simplified - you might need to handle string references differently
                            //     if let Reference::Integer(val) = &tcb_status_prop.reference {
                            //         status = Some(*val);
                            //     }
                            // }
                        }
                        PolicyTypes::MigTD(migtd) => {
                            // Extract SVN from MigTdPolicy
                            if let Reference::Integer(val) = &migtd.migtd_identity.svn.reference {
                                svn = Some(*val);
                            }
                        }
                    }
                }

                (date, eval_num, svn)
            };

        let policy_block = match block_type {
            PolicyBlockType::Common => &policy.policy.common_policy,
            PolicyBlockType::Forward => &policy.policy.forward_policy,
            PolicyBlockType::Backward => &policy.policy.backward_policy,
        };

        // Extract from policy block (as base values)
        if let Some(common) = policy_block {
            let (date, eval_num, svn) = extract_from_block(common);
            tcb_date = date;
            tcb_evaluation_number = eval_num;
            engine_svn = svn;
        }

        PolicyEvaluationInfo {
            tcb_date,
            tcb_status,
            tcb_evaluation_number,
            engine_svn,
        }
    }
}

#[derive(Clone, Copy)]
pub enum PolicyBlockType {
    Common,
    Forward,
    Backward,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    id: String,
    version: String,
    #[serde(rename = "forward-policy")]
    common_policy: Option<Vec<PolicyTypes>>,
    #[serde(rename = "forward-policy")]
    forward_policy: Option<Vec<PolicyTypes>>,
    #[serde(rename = "backward-policy")]
    backward_policy: Option<Vec<PolicyTypes>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PolicyTypes {
    Global(GlobalPolicy),
    MigTD(MigTdPolicy),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Global {
    #[serde(rename = "Global")]
    global_policy: GlobalPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalPolicy {
    #[serde(rename = "TcbNumber")]
    pub tcb_number: TcbNumberPolicy,
}

impl GlobalPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.tcb_number.tcb_evaluation_data_number {
            if let Some(tcb_evaluation_number) = value.tcb_evaluation_number {
                if !property.evaluate_integer(
                    tcb_evaluation_number,
                    relative_reference.tcb_evaluation_number,
                )? {
                    return Err(PolicyError::TcbEvaluation);
                }
            }
        }

        if let Some(tcb_status_policy) = &self.tcb_number.tcb_status {
            if !tcb_status_policy.evaluate_string(
                value
                    .tcb_status
                    .as_deref()
                    .ok_or(PolicyError::TcbEvaluation)?,
                relative_reference.tcb_status.as_deref(),
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        if let Some(tcb_date_policy) = &self.tcb_number.tcb_date {
            if !tcb_date_policy.evaluate_string(
                &value
                    .tcb_date
                    .as_deref()
                    .ok_or(PolicyError::TcbEvaluation)?,
                relative_reference.tcb_date.as_deref(),
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbNumberPolicy {
    pub tcb_date: Option<PolicyProperty>,
    pub tcb_status: Option<PolicyProperty>,
    pub tcb_evaluation_data_number: Option<PolicyProperty>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTd {
    #[serde(rename = "MigTD")]
    pub migtd_policy: MigTdPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTdPolicy {
    #[serde(rename = "MigTdIdentity")]
    pub migtd_identity: MigTdIdentityPolicy,
}

impl MigTdPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if !self.migtd_identity.svn.evaluate_integer(
            value.engine_svn.ok_or(PolicyError::UnqulifiedMigTdInfo)?,
            relative_reference.engine_svn,
        )? {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigTdIdentityPolicy {
    #[serde(rename = "SVN")]
    pub svn: PolicyProperty,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Reference {
    Integer(u32),
    String(String),
    IntegerList(Vec<u32>),
    StringList(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyField {
    operation: String,
    reference: Reference,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyProperty {
    pub operation: String,
    pub reference: Reference,
}

impl PolicyProperty {
    pub fn validate(&self, block_type: PolicyBlockType) -> bool {
        if self.operation.is_empty() {
            return false;
        }
        match &self.reference {
            Reference::String(s) => {
                if s.is_empty() {
                    return false;
                }

                // Check reference string based on policy block type
                match block_type {
                    PolicyBlockType::Common => s != "self" && s != "init",
                    PolicyBlockType::Forward => s != "init",
                    PolicyBlockType::Backward => s != "self",
                }
            }
            _ => true,
        }
    }

    pub fn evaluate_integer(
        &self,
        value: u32,
        relative_reference: Option<u32>,
    ) -> Result<bool, PolicyError> {
        let is_in_range = |value: &u32, range: &str| -> Result<bool, PolicyError> {
            let parts = range.split("..").collect::<Vec<&str>>();
            if parts.len() != 2 {
                return Err(PolicyError::InvalidOperation);
            }
            let start = parts[0]
                .parse::<u32>()
                .map_err(|_| PolicyError::InvalidReference)?;
            let end = parts[1]
                .parse::<u32>()
                .map_err(|_| PolicyError::InvalidReference)?;

            Ok(*value >= start && *value <= end)
        };

        match &self.reference {
            Reference::Integer(reference) => match self.operation.as_str() {
                "equal" => Ok(value == *reference),
                "greater-or-equal" => Ok(value >= *reference),
                _ => return Err(PolicyError::InvalidOperation),
            },
            Reference::String(reference) => {
                if reference != "self" || reference != "init" {
                    return Err(PolicyError::InvalidReference);
                }
                let relative_reference = relative_reference.ok_or(PolicyError::InvalidReference)?;
                match self.operation.as_str() {
                    "equal" => Ok(value == relative_reference),
                    "greater-or-equal" => Ok(value >= relative_reference),
                    "in-range" => is_in_range(&value, &reference),
                    "in-time-range" => is_in_range(&value, &reference),
                    _ => Err(PolicyError::InvalidOperation),
                }
            }
            Reference::IntegerList(items) => match self.operation.as_str() {
                "subset" => Ok(items.contains(&value)),
                _ => Err(PolicyError::InvalidOperation),
            },
            _ => Err(PolicyError::InvalidReference),
        }
    }

    pub fn evaluate_integer_list(
        &self,
        values: &[u32],
        relative_reference: Option<&[u32]>,
    ) -> Result<bool, PolicyError> {
        let integer_list_op = |values: &[u32], reference: &[u32]| {
            match self.operation.as_str() {
                "array-equal" => {
                    for (i, val) in values.iter().enumerate() {
                        if *val != reference[i] {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                "array-greater-or-equal" => {
                    // Each value in input must be >= corresponding value in reference at same position
                    for (i, val) in values.iter().enumerate() {
                        if *val < reference[i] {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                _ => panic!("Invalid operation"),
            }
        };

        match &self.reference {
            Reference::IntegerList(reference) => {
                if values.len() != reference.len() {
                    return Ok(false);
                }
                integer_list_op(values, &reference)
            }
            Reference::String(reference) => {
                if reference != "self" || reference != "init" {
                    return Err(PolicyError::InvalidReference);
                }
                let relative_reference = relative_reference.ok_or(PolicyError::InvalidReference)?;
                integer_list_op(values, relative_reference)
            }
            _ => Err(PolicyError::InvalidReference),
        }
    }

    /// Evaluate a String property against a reference value
    pub fn evaluate_string(
        &self,
        value: &str,
        relative_reference: Option<&str>,
    ) -> Result<bool, PolicyError> {
        match &self.reference {
            Reference::String(reference) => {
                let reference_value = match reference.as_str() {
                    "self" | "init" => relative_reference.ok_or(PolicyError::InvalidReference)?,
                    other => other,
                };
                match self.operation.as_str() {
                    "equal" => Ok(value == reference_value),
                    "greater-or-equal" => {
                        // Simple lexicographical comparison works for ISO-8601 format (e.g. "2025-01-01T00:00:00Z")
                        // This is because ISO-8601 is designed to be sortable as strings
                        Ok(value >= reference_value)
                    }
                    _ => Err(PolicyError::InvalidOperation),
                }
            }
            Reference::StringList(reference) => match self.operation.as_str() {
                "allow-list" => {
                    if reference.iter().any(|item| item == value) {
                        return Ok(true);
                    }
                    Ok(false)
                }
                "deny-list" => {
                    if reference.iter().any(|item| item == value) {
                        return Ok(false);
                    }
                    Ok(true)
                }
                _ => Err(PolicyError::InvalidOperation),
            },
            _ => Err(PolicyError::InvalidReference),
        }
    }
}

// #[derive(Debug, Serialize, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct PolicyOperation<T> {
//     pub operation: String,
//     pub reference: T,
// }

// impl PolicyOperation<u32> {
//     /// Evaluate a u32 operation against a reference value
//     ///
//     /// - equal: the value must be equal to the reference
//     /// - greater-or-equal: the value must be greater than or equal to the reference
//     pub fn evaluate(&self, value: u32) -> Result<bool, PolicyError> {
//         match self.operation.as_str() {
//             "equal" => Ok(value == self.reference),
//             "greater-or-equal" => Ok(value >= self.reference),
//             _ => Err(PolicyError::InvalidOperation),
//         }
//     }
// }

// impl PolicyOperation<Vec<u32>> {
//     /// Evaluate a value against an array reference
//     ///
//     /// - subset: the value must be equal to at least one value in the array
//     pub fn evaluate(&self, value: u32) -> Result<bool, PolicyError> {
//         match self.operation.as_str() {
//             "subset" => Ok(self.reference.contains(&value)),
//             _ => Err(PolicyError::InvalidOperation),
//         }
//     }

//     /// Evaluate a vector of values against the reference
//     ///
//     /// - array-equal: All values in reference must match the input
//     /// - array-greater-or-equal: The input must be >= every value in reference
//     pub fn evaluate_vec(&self, values: &[u32]) -> Result<bool, PolicyError> {
//         match self.operation.as_str() {
//             "array-equal" => {
//                 if values.len() != self.reference.len() {
//                     return Ok(false);
//                 }

//                 for (i, val) in values.iter().enumerate() {
//                     if *val != self.reference[i] {
//                         return Ok(false);
//                     }
//                 }

//                 Ok(true)
//             }
//             "array-greater-or-equal" => {
//                 if values.len() != self.reference.len() {
//                     return Ok(false);
//                 }

//                 // Each value in input must be >= corresponding value in reference at same position
//                 for (i, val) in values.iter().enumerate() {
//                     if *val < self.reference[i] {
//                         return Ok(false);
//                     }
//                 }

//                 Ok(true)
//             }
//             _ => Err(PolicyError::InvalidOperation),
//         }
//     }
// }

// impl PolicyOperation<String> {
//     /// Evaluate a String operation against a reference value
//     ///
//     /// * For normal string references, directly compare with the value
//     /// * For "self" reference, compare with the original provided value
//     /// * For "init" reference, compare with the optional initial value if provided
//     pub fn evaluate(
//         &self,
//         value: &str,
//         self_value: &str,
//         init_value: &str,
//     ) -> Result<bool, PolicyError> {
//         let reference_value = match self.reference.as_str() {
//             "self" => self_value,
//             "init" => init_value,
//             other => other,
//         };

//         let is_in_range = |value: &str, range: &str| -> Result<bool, PolicyError> {
//             let parts = range.split("..").collect::<Vec<&str>>();
//             if parts.len() != 2 {
//                 return Err(PolicyError::InvalidOperation);
//             }
//             let start = parts[0]
//                 .parse::<u32>()
//                 .map_err(|_| PolicyError::InvalidReference)?;
//             let end = parts[1]
//                 .parse::<u32>()
//                 .map_err(|_| PolicyError::InvalidReference)?;
//             let value_num = value
//                 .parse::<u32>()
//                 .map_err(|_| PolicyError::InvalidReference)?;

//             Ok(value_num >= start && value_num <= end)
//         };

//         match self.operation.as_str() {
//             "equal" => Ok(value == reference_value),
//             "greater-or-equal" => {
//                 // Simple lexicographical comparison works for ISO-8601 format (e.g. "2025-01-01T00:00:00Z")
//                 // This is because ISO-8601 is designed to be sortable as strings
//                 Ok(value >= reference_value)
//             }
//             "in-range" => is_in_range(value, reference_value),
//             "in-time-range" => is_in_range(value, reference_value),
//             _ => Err(PolicyError::InvalidOperation),
//         }
//     }
// }

// impl PolicyOperation<Vec<String>> {
//     /// Evaluate a String operation against a reference value list
//     ///
//     /// - allow-list: the value must be in the reference list
//     /// - deny-list: the value must not be in the reference list
//     pub fn evaluate(&self, value: &str) -> Result<bool, PolicyError> {
//         match self.operation.as_str() {
//             "allow-list" => {
//                 if self.reference.iter().any(|item| item == value) {
//                     return Ok(true);
//                 }
//                 Ok(false)
//             }
//             "deny-list" => {
//                 if self.reference.iter().any(|item| item == value) {
//                     return Ok(false);
//                 }
//                 Ok(true)
//             }
//             _ => Err(PolicyError::InvalidOperation),
//         }
//     }
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialEngineSvnMap<'a> {
    #[serde(borrow)]
    engine_svn: &'a RawValue,
    signature: Option<String>,
}

impl<'a> PartialEngineSvnMap<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<PartialEngineSvnMap>(slice)
            .map_err(|_| PolicyError::InvalidEngineSvnMap)
    }

    pub fn sign(&mut self, signing_key: &[u8]) -> Result<(), PolicyError> {
        let signature = ecdsa_p384_sign(self.engine_svn.get().as_bytes(), signing_key)?;
        self.signature = Some(bytes_to_hex_string(&signature));

        Ok(())
    }
}

impl TryInto<EngineSvnMap> for PartialEngineSvnMap<'_> {
    type Error = PolicyError;
    fn try_into(self) -> Result<EngineSvnMap, Self::Error> {
        let engine_svn = serde_json::from_str(self.engine_svn.get())
            .map_err(|_| PolicyError::InvalidEngineSvnMap)?;
        Ok(EngineSvnMap {
            engine_svn,
            signature: self.signature.ok_or(PolicyError::InvalidEngineSvnMap)?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EngineSvn {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub svn: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EngineSvnMap {
    pub engine_svn: Vec<EngineSvn>,
    pub signature: String,
}

impl EngineSvnMap {
    pub fn get_engine_svn(&self, report: &Report) -> Option<u32> {
        self.get_engine_svn_by_values(
            report
                .get_migtd_info_property(&MigTdInfoProperty::MrTd)
                .ok()?,
            report
                .get_migtd_info_property(&MigTdInfoProperty::Rtmr0)
                .ok()?,
            report
                .get_migtd_info_property(&MigTdInfoProperty::Rtmr1)
                .ok()?,
        )
    }

    fn get_engine_svn_by_values(&self, mrtd: &[u8], rtmr0: &[u8], rtmr1: &[u8]) -> Option<u32> {
        self.engine_svn.iter().find_map(|engine| {
            if engine.mrtd.as_bytes() == mrtd
                && engine.rtmr0.as_bytes() == rtmr0
                && engine.rtmr1.as_bytes() == rtmr1
            {
                Some(engine.svn)
            } else {
                None
            }
        })
    }
}

/// Convert a hex string to bytes without using external crates
fn hex_string_to_bytes(hex: &str) -> Result<Vec<u8>, PolicyError> {
    // Ensure even number of characters
    if hex.len() % 2 != 0 {
        return Err(PolicyError::SignatureVerificationFailed);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    // Process two hex digits at a time
    for i in (0..hex.len()).step_by(2) {
        if i + 2 > hex.len() {
            break;
        }

        // Get the hex byte as a string slice
        let byte_str = &hex[i..i + 2];

        // Convert to numeric value
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

        bytes.push(byte);
    }

    Ok(bytes)
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// Convert ECDSA DER public key to raw bytes (04 || x || y)
fn ecdsa_der_pubkey_to_raw(der_pubkey: &[u8]) -> Result<Vec<u8>, PolicyError> {
    // Check for SEQUENCE tag
    if der_pubkey.len() < 2 || der_pubkey[0] != 0x30 {
        return Err(PolicyError::Crypto);
    }

    // Find the BIT STRING tag (0x03) that contains the actual key
    let mut pos = 0;
    while pos < der_pubkey.len() - 2 {
        if der_pubkey[pos] == 0x03 {
            // Found BIT STRING
            pos += 1;

            // Get length
            let len = der_pubkey[pos] as usize;
            pos += 1;

            // Skip unused bits byte
            pos += 1;

            // The rest is the key data
            return Ok(der_pubkey[pos..pos + len - 1].to_vec());
        }
        pos += 1;
    }

    Err(PolicyError::Crypto)
}

fn get_sha384_hash(data: &[u8]) -> Result<[u8; 48], PolicyError> {
    let mut hash = [0u8; 48]; // SHA-384 produces a 48-byte hash

    let digest = ring::digest::digest(&ring::digest::SHA384, data);
    let digest_bytes = digest.as_ref();

    // Copy the digest to our fixed-size array
    if digest_bytes.len() != hash.len() {
        return Err(PolicyError::HashCalculation);
    }

    hash.copy_from_slice(digest_bytes);
    Ok(hash)
}

fn verify_ecdsa_384_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), PolicyError> {
    let public_key = ecdsa_der_pubkey_to_raw(public_key).map_err(|_| PolicyError::Crypto)?;

    // Verify the signature with `ring`
    let signature_verifier = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &public_key);
    signature_verifier
        .verify(data, signature)
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    Ok(())
}

fn ecdsa_p384_sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let rng = rand::SystemRandom::new();
    let ecdsa_key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, private_key, &rng)
            .map_err(|_| PolicyError::Crypto)?;

    let signature = ecdsa_key_pair
        .sign(&rng, data)
        .map_err(|_| PolicyError::Crypto)?
        .as_ref()
        .to_vec();
    Ok(signature)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{string::ToString, vec};

    #[test]
    fn test_hex_string_to_bytes() {
        // Test valid hex strings
        assert_eq!(
            hex_string_to_bytes("48656c6c6f").unwrap(),
            vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]
        );
        assert_eq!(
            hex_string_to_bytes("ff00ff").unwrap(),
            vec![0xff, 0x00, 0xff]
        );

        // Test invalid hex strings
        assert!(hex_string_to_bytes("123g").is_err());
        assert!(hex_string_to_bytes("123").is_err()); // Odd length
    }

    #[test]
    fn test_verify_policy_signature() {
        let policy_bytes = include_bytes!("../../test/policy_v2/policy.json");
        let public_key = include_bytes!("../../test/policy_v2/policy-public.der");
        verify_policy_signature(policy_bytes, public_key).unwrap();
    }

    #[test]
    fn test_verify_engine_signature() {
        let engine_bytes = include_bytes!("../../test/policy_v2/engine.json");
        let public_key = include_bytes!("../../test/policy_v2/engine-public.der");
        verify_engine_signature(engine_bytes, public_key).unwrap();
    }

    #[test]
    fn test_get_engine_svn() {
        let engine_bytes = include_bytes!("../../test/policy_v2/engine.json");
        let engine: EngineSvnMap = serde_json::from_slice(engine_bytes).unwrap();

        let mrtd = b"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let rtmr0 = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let rtmr1 = b"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        assert_eq!(engine.get_engine_svn_by_values(mrtd, rtmr0, rtmr1), Some(1));

        let mrtd = b"01234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde";
        let rtmr0 = b"bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890a";
        let rtmr1 = b"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        assert!(engine
            .get_engine_svn_by_values(mrtd, rtmr0, rtmr1)
            .is_none());
    }

    #[test]
    fn test_policy_tcb_date() {
        // Test with a value reference
        let tcb_date_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("2025-01-01T00:00:00Z".to_string()),
        };
        assert!(tcb_date_policy
            .evaluate_string("2025-06-15T12:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
        assert!(!tcb_date_policy
            .evaluate_string("2024-01-01T00:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());

        // Test with "self" reference
        let tcb_date_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("self".to_string()),
        };
        assert!(tcb_date_policy
            .evaluate_string("2025-06-15T12:01:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
        assert!(!tcb_date_policy
            .evaluate_string("2025-06-15T11:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
    }

    #[test]
    fn test_policy_tcb_status() {
        // Test with an "allow-list" operation
        let tcb_status_policy = PolicyProperty {
            operation: "allow-list".to_string(),
            reference: Reference::StringList(vec![
                "UpToDate".to_string(),
                "SwHardeningNeeded".to_string(),
                "ConfigurationNeeded".to_string(),
            ]),
        };
        let relative_reference = "null";
        assert!(
            tcb_status_policy
                .evaluate_string("UpToDate", Some(relative_reference))
                .unwrap()
                && tcb_status_policy
                    .evaluate_string("SwHardeningNeeded", Some(relative_reference))
                    .unwrap()
                && tcb_status_policy
                    .evaluate_string("ConfigurationNeeded", Some(relative_reference))
                    .unwrap()
        );
        assert!(
            !(tcb_status_policy
                .evaluate_string("OutOfDate", Some(relative_reference))
                .unwrap()
                || tcb_status_policy
                    .evaluate_string("OutOfDateConfigurationNeeded", Some(relative_reference))
                    .unwrap()
                || tcb_status_policy
                    .evaluate_string("Revoked", Some(relative_reference))
                    .unwrap())
        );

        // Test with "deny-list" reference
        let tcb_status_policy = PolicyProperty {
            operation: "deny-list".to_string(),
            reference: Reference::StringList(vec![
                "Revoked".to_string(),
                "OutOfDateConfigurationNeeded".to_string(),
            ]),
        };
        assert!(
            tcb_status_policy
                .evaluate_string("UpToDate", Some(relative_reference))
                .unwrap()
                && tcb_status_policy
                    .evaluate_string("SwHardeningNeeded", Some(relative_reference))
                    .unwrap()
                && tcb_status_policy
                    .evaluate_string("ConfigurationNeeded", Some(relative_reference))
                    .unwrap()
                && tcb_status_policy
                    .evaluate_string("OutOfDate", Some(relative_reference))
                    .unwrap()
        );
        assert!(
            !(tcb_status_policy
                .evaluate_string("OutOfDateConfigurationNeeded", Some(relative_reference))
                .unwrap()
                || tcb_status_policy
                    .evaluate_string("Revoked", Some(relative_reference))
                    .unwrap())
        );
    }

    #[test]
    fn test_policy_tcb_evaluation_number() {
        // Test with a value reference
        let tcb_evaluation_number_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::Integer(5),
        };
        let relative_reference = u32::MAX;
        assert!(
            tcb_evaluation_number_policy
                .evaluate_integer(5, Some(relative_reference))
                .unwrap()
                && tcb_evaluation_number_policy
                    .evaluate_integer(10, Some(relative_reference))
                    .unwrap()
        );
        assert!(!tcb_evaluation_number_policy
            .evaluate_integer(4, Some(relative_reference))
            .unwrap());
    }

    #[test]
    fn test_gen_policy() {
        extern crate std;

        let policy = Policy {
            id: "5752E5CA-1E06-4883-A110-2D4405D35BAD".to_string(),
            version: 2.to_string(),
            common_policy: Some(vec![
                PolicyTypes::Global(GlobalPolicy {
                    tcb_number: TcbNumberPolicy {
                        tcb_evaluation_data_number: Some(PolicyProperty {
                            operation: "greater-or-equal".to_string(),
                            reference: Reference::Integer(3),
                        }),
                        tcb_status: Some(PolicyProperty {
                            operation: "allow-list".to_string(),
                            reference: Reference::StringList(vec![
                                "UpToDate".to_string(),
                                "ConfigurationNeeded".to_string(),
                                "SWHardeningNeeded".to_string(),
                            ]),
                        }),
                        tcb_date: None,
                    },
                }),
                PolicyTypes::MigTD(MigTdPolicy {
                    migtd_identity: MigTdIdentityPolicy {
                        svn: PolicyProperty {
                            operation: "greater-or-equal".to_string(),
                            reference: Reference::Integer(5),
                        },
                    },
                }),
            ]),
            forward_policy: None,
            backward_policy: None,
        };
        let signing_key = include_bytes!("../../test/policy_v2/policy-private.pk8");
        let policy_json = serde_json::to_string(&policy).unwrap();
        let raw = RawValue::from_string(policy_json).unwrap();
        let mut partial_policy = PartialMigPolicy {
            policy: &raw,
            signature: None,
        };
        partial_policy.sign(signing_key).unwrap();

        let policy_json = serde_json::to_string(&partial_policy).unwrap();
        std::fs::write("test/policy_v2/policy.json", policy_json).unwrap();
    }

    #[test]
    fn test_gen_engine() {
        extern crate std;

        let engine_svn = vec![EngineSvn {
            mrtd: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            rtmr0: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            rtmr1: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
            svn: 1,
        }];

        let signing_key = include_bytes!("../../test/policy_v2/engine-private.pk8");
        let engine_svn_json = serde_json::to_string(&engine_svn).unwrap();
        let raw = RawValue::from_string(engine_svn_json).unwrap();
        let mut partial_engine_svn_map = PartialEngineSvnMap {
            engine_svn: &raw,
            signature: None,
        };
        partial_engine_svn_map.sign(signing_key).unwrap();

        let engine_json = serde_json::to_string(&partial_engine_svn_map).unwrap();
        std::fs::write("test/policy_v2/engine.json", engine_json).unwrap();
    }
}
