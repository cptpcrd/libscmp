// This must run in a test of its own so it runs in a separate process (not just a separate thread)
// and doesn't interfere with other tests.

#[test]
fn test_api_get_set() {
    let orig_api = libscmp::api_get();

    for &api in [1, 2, 3, orig_api].iter() {
        libscmp::api_set(api).unwrap();
        assert_eq!(libscmp::api_get(), api);
    }
}
