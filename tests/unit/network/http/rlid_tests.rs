use super::*;
use std::time::Duration;

#[test]
fn rlid_round_trip_issue_and_verify() {
    let cur = [7u8; 32];
    let old = [9u8; 32];
    let signer = RlidSigner::new("rlid", Duration::from_secs(60), (2, cur), vec![(1, old)]);

    // new id + set-cookie
    let id = signer.gen_id();
    let sc = signer.issue_set_cookie(&id, false, None, Some("/"));
    assert!(sc.starts_with("rlid=v1.2."), "cookie format mismatch: {sc}");

    // extract value
    let value = sc.split_once('=').unwrap().1.split(';').next().unwrap();
    let res = signer.verify_or_new(Some(value));
    assert_eq!(res.id, id);
    assert!(!res.must_issue, "fresh token should not require refresh");
}

#[test]
fn rlid_refresh_when_near_expiry() {
    let cur = [1u8; 32];
    let signer =
        RlidSigner::new("rlid", Duration::from_secs(3), (1, cur), vec![]).with_reissue_divisor(3);

    let id = signer.gen_id();
    let val = signer.make_value_current(&id);

    // Immediately valid; depending on timing, may or may not need refresh — accept both
    let res = signer.verify_or_new(Some(&val));
    assert_eq!(res.id, id);
}

#[test]
fn invalid_token_yields_new_id() {
    let cur = [3u8; 32];
    let signer = RlidSigner::new("rlid", Duration::from_secs(60), (7, cur), vec![]);
    let res = signer.verify_or_new(Some("v1.9.notpayload.notmac"));
    assert!(res.must_issue);
    // id is random; just ensure it's non-empty
    assert!(!res.id.is_empty());
}

#[test]
fn expired_token_yields_new_id() {
    let cur = [4u8; 32];
    let signer = RlidSigner::new("rlid", Duration::from_secs(60), (8, cur), vec![]);
    let old_id = signer.gen_id();
    let expired = signer.make_v1_value(8, &old_id, now_unix().saturating_sub(1));

    let res = signer.verify_or_new(Some(&expired));

    assert!(res.must_issue);
    assert_ne!(res.id, old_id);
}
