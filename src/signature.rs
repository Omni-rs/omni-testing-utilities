use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self};
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_primitives::views::{ExecutionStatusView, FinalExecutionStatus};

pub fn extract_big_r_and_s(response: &RpcTransactionResponse) -> Result<(String, String), String> {
    if let Some(near_primitives::views::FinalExecutionOutcomeViewEnum::FinalExecutionOutcome(
        final_outcome,
    )) = &response.final_execution_outcome
    {
        if let FinalExecutionStatus::SuccessValue(success_value) = &final_outcome.status {
            let success_value_str =
                String::from_utf8(success_value.clone()).map_err(|e| e.to_string())?;
            let inner: serde_json::Value =
                serde_json::from_str(&success_value_str).map_err(|e| e.to_string())?;

            let big_r = inner["big_r"]["affine_point"]
                .as_str()
                .ok_or("Missing big_r affine_point")?;
            let s = inner["s"]["scalar"].as_str().ok_or("Missing s scalar")?;

            return Ok((big_r.to_string(), s.to_string()));
        }
    }

    Err("Failed to extract big_r and s".to_string())
}

pub fn create_signature(big_r_hex: &str, s_hex: &str) -> Result<Signature, secp256k1::Error> {
    // Convert hex strings to byte arrays
    let big_r_bytes = hex::decode(big_r_hex).unwrap();
    let s_bytes = hex::decode(s_hex).unwrap();

    // Remove the first byte from big_r (compressed point indicator)
    let big_r_x_bytes = &big_r_bytes[1..];

    // Ensure the byte arrays are the correct length
    if big_r_x_bytes.len() != 32 || s_bytes.len() != 32 {
        return Err(secp256k1::Error::InvalidSignature);
    }

    // Create the signature from the bytes
    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(big_r_x_bytes);
    signature_bytes[32..].copy_from_slice(&s_bytes);

    // Create the signature object
    let signature = Signature::from_compact(&signature_bytes)?;

    Ok(signature)
}

pub fn extract_multiple_signatures(
    response: &RpcTransactionResponse,
) -> Result<Vec<(String, String)>, String> {
    let mut signatures = Vec::new();

    if let Some(near_primitives::views::FinalExecutionOutcomeViewEnum::FinalExecutionOutcome(
        final_outcome,
    )) = &response.final_execution_outcome
    {
        for receipt in &final_outcome.receipts_outcome {
            if let ExecutionStatusView::SuccessValue(success_value) = &receipt.outcome.status {
                if let Ok(success_value_str) = String::from_utf8(success_value.clone()) {
                    if let Ok(inner) = serde_json::from_str::<serde_json::Value>(&success_value_str)
                    {
                        if let (Some(big_r), Some(s)) = (
                            inner["big_r"]["affine_point"].as_str(),
                            inner["s"]["scalar"].as_str(),
                        ) {
                            signatures.push((big_r.to_string(), s.to_string()));
                        }
                    }
                }
            }
        }
    }

    if signatures.is_empty() {
        return Err("No signatures found".to_string());
    }

    Ok(signatures)
}
