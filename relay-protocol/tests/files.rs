use tau_relay_protocol::{Principal, files::*};

fn hash_hex(bytes: &[u8]) -> String {
    mtp::crypto::sha256(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn detached_file_signing_bytes_match_client_golden_hashes() {
    let origin =
        Principal::new(format!("omega-key:{}", "a".repeat(64)), i64::MAX as u64 - 1).unwrap();
    let recipient =
        Principal::new(format!("omega-key:{}", "b".repeat(64)), i64::MAX as u64).unwrap();
    let key = FileKey {
        origin,
        file_id: "golden-file".into(),
        version: i64::MAX,
    };
    let offer = ShareOffer {
        manifest: FileManifest {
            key: key.clone(),
            ciphertext_sha256: vec![7; 32],
            ciphertext_size: 65576,
            crypto_format: "tensamin-file-chunks-v1".into(),
            manifest_ciphertext: vec![8; 41],
            envelope: KeyEnvelope {
                recipient: recipient.clone(),
                key_id: "recipient-key".into(),
                wrapping_scheme: "tensamin-file-dek-kem-v1".into(),
                kem_ciphertext: vec![0, 1, 255],
                encrypted_dek: vec![9; 72],
            },
        },
        chat_id: "fixture-chat".into(),
        grant_revision: i64::MAX - 1,
        expires_at: i64::MAX,
        signing_public_key: "AQ==".into(),
        signature: vec![],
    };
    assert_eq!(
        hash_hex(&offer.signing_bytes()),
        "0352ed5f8541ecf28befb368399dc9c9b44b8ca80aa8dc984b41b7316bfd55a4"
    );
    let revoke = ShareRevoke {
        key,
        recipient,
        chat_id: "fixture-chat".into(),
        grant_revision: i64::MAX,
        signing_public_key: "AQ==".into(),
        signature: vec![],
    };
    assert_eq!(
        hash_hex(&revoke.signing_bytes()),
        "6c55f0ecadce8ad636214ddf95c4da3dcd88f8f55375f37239225c08fab2a7a7"
    );
}
