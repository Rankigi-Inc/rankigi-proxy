use rankigi_proxy::proxy::http_reason;

#[test]
fn http_reason_known_status() {
    assert_eq!(http_reason(200), "OK");
    assert_eq!(http_reason(404), "Not Found");
    assert_eq!(http_reason(500), "Internal Server Error");
    assert_eq!(http_reason(307), "Temporary Redirect");
    assert_eq!(http_reason(422), "Unprocessable Content");
}

#[test]
fn http_reason_unknown_status() {
    assert_eq!(http_reason(418), "Unknown");
    assert_eq!(http_reason(999), "Unknown");
}
