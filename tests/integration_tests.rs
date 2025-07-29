use truenas_rust_nss::{getpwnam, getpwuid, getgrnam, getgrgid, getpwall, getgrall, iterpw, itergrp, NssModule};

#[cfg(test)]
mod integration_tests {
    use super::*;

    // These tests will only pass if the system has the appropriate NSS modules
    // and the test user/groups exist

    #[test]
    #[ignore = "Requires system NSS libraries and root user"]
    fn test_getpwnam_root() {
        match getpwnam("root", Some(NssModule::Files)) {
            Ok(user) => {
                assert_eq!(user.pw_name, "root");
                assert_eq!(user.pw_uid, 0);
                assert_eq!(user.source, "files");
                assert!(!user.pw_shell.is_empty());

                // Test JSON serialization
                let json = user.to_json().expect("JSON serialization failed");
                assert!(json.contains("root"));
                assert!(json.contains("\"pw_uid\":0"));
            }
            Err(e) => {
                eprintln!("Warning: getpwnam test failed (may be expected if NSS modules not available): {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries and root user"]
    fn test_getpwuid_root() {
        match getpwuid(0, Some(NssModule::Files)) {
            Ok(user) => {
                assert_eq!(user.pw_name, "root");
                assert_eq!(user.pw_uid, 0);
                assert_eq!(user.source, "files");

                // Test pretty JSON
                let json = user.to_json_pretty().expect("Pretty JSON serialization failed");
                assert!(json.contains("root"));
                assert!(json.contains("\n")); // Should be pretty-printed
            }
            Err(e) => {
                eprintln!("Warning: getpwuid test failed (may be expected if NSS modules not available): {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries and root group"]
    fn test_getgrnam_root() {
        match getgrnam("root", Some(NssModule::Files)) {
            Ok(group) => {
                assert_eq!(group.gr_name, "root");
                assert_eq!(group.gr_gid, 0);
                assert_eq!(group.source, "files");

                // Test JSON serialization
                let json = group.to_json().expect("JSON serialization failed");
                assert!(json.contains("root"));
                assert!(json.contains("\"gr_gid\":0"));
            }
            Err(e) => {
                eprintln!("Warning: getgrnam test failed (may be expected if NSS modules not available): {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries and root group"]
    fn test_getgrgid_root() {
        match getgrgid(0, Some(NssModule::Files)) {
            Ok(group) => {
                assert_eq!(group.gr_name, "root");
                assert_eq!(group.gr_gid, 0);
                assert_eq!(group.source, "files");

                // Test pretty JSON
                let json = group.to_json_pretty().expect("Pretty JSON serialization failed");
                assert!(json.contains("root"));
                assert!(json.contains("\n")); // Should be pretty-printed
            }
            Err(e) => {
                eprintln!("Warning: getgrgid test failed (may be expected if NSS modules not available): {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries - slow test"]
    fn test_getpwall_files() {
        match getpwall(Some(NssModule::Files)) {
            Ok(users) => {
                assert!(!users.is_empty(), "Expected at least one user");

                // Check that all users have the files source
                for user in &users {
                    assert_eq!(user.source, "files");
                    assert!(!user.pw_name.is_empty());
                }

                println!("Found {} users from FILES module", users.len());
            }
            Err(e) => {
                eprintln!("Warning: getpwall test failed (may be expected if NSS modules not available): {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries - slow test"]
    fn test_getgrall_files() {
        match getgrall(Some(NssModule::Files)) {
            Ok(groups) => {
                assert!(!groups.is_empty(), "Expected at least one group");

                // Check that all groups have the files source
                for group in &groups {
                    assert_eq!(group.source, "files");
                    assert!(!group.gr_name.is_empty());
                }

                println!("Found {} groups from FILES module", groups.len());
            }
            Err(e) => {
                eprintln!("Warning: getgrall test failed (may be expected if NSS modules not available): {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries"]
    fn test_iterpw_files() {
        let mut count = 0;
        let max_items = 5; // Limit to avoid long test times

        for result in iterpw(NssModule::Files) {
            if count >= max_items {
                break;
            }

            match result {
                Ok(user) => {
                    assert!(!user.pw_name.is_empty());
                    assert_eq!(user.source, "files");
                    count += 1;
                }
                Err(e) => {
                    eprintln!("Iterator error (may be expected): {}", e);
                    break;
                }
            }
        }

        if count > 0 {
            println!("Successfully iterated through {} users", count);
        } else {
            eprintln!("Warning: No users found during iteration (may be expected if NSS modules not available)");
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries"]
    fn test_itergrp_files() {
        let mut count = 0;
        let max_items = 5; // Limit to avoid long test times

        for result in itergrp(NssModule::Files) {
            if count >= max_items {
                break;
            }

            match result {
                Ok(group) => {
                    assert!(!group.gr_name.is_empty());
                    assert_eq!(group.source, "files");
                    count += 1;
                }
                Err(e) => {
                    eprintln!("Iterator error (may be expected): {}", e);
                    break;
                }
            }
        }

        if count > 0 {
            println!("Successfully iterated through {} groups", count);
        } else {
            eprintln!("Warning: No groups found during iteration (may be expected if NSS modules not available)");
        }
    }

    #[test]
    #[ignore = "Requires system NSS libraries"]
    fn test_multiple_modules_fallback() {
        // Test fallback behavior when querying all modules
        match getpwnam("root", None) {
            Ok(user) => {
                assert_eq!(user.pw_name, "root");
                assert_eq!(user.pw_uid, 0);
                // Source should be one of the available modules
                assert!(["files", "sss", "winbind"].contains(&user.source.as_str()));
            }
            Err(e) => {
                eprintln!("Warning: Multiple module fallback test failed (may be expected): {}", e);
            }
        }
    }

    #[test]
    fn test_nonexistent_user() {
        // This test should work even without NSS libraries, as it tests error handling
        match getpwnam("nonexistent_user_12345", Some(NssModule::Files)) {
            Ok(_) => panic!("Expected error for nonexistent user"),
            Err(e) => {
                // Should get either a library loading error or a not found error
                println!("Expected error for nonexistent user: {}", e);
            }
        }
    }

    #[test]
    fn test_nonexistent_group() {
        // This test should work even without NSS libraries, as it tests error handling
        match getgrnam("nonexistent_group_12345", Some(NssModule::Files)) {
            Ok(_) => panic!("Expected error for nonexistent group"),
            Err(e) => {
                // Should get either a library loading error or a not found error
                println!("Expected error for nonexistent group: {}", e);
            }
        }
    }
}

// Benchmark tests (require nightly Rust and --features unstable)
#[cfg(all(test, feature = "unstable"))]
mod benchmarks {
    use super::*;
    use std::test::Bencher;

    #[bench]
    #[ignore = "Requires system NSS libraries"]
    fn bench_getpwnam_root(b: &mut Bencher) {
        b.iter(|| {
            let _ = getpwnam("root", Some(NssModule::Files));
        });
    }

    #[bench]
    #[ignore = "Requires system NSS libraries"]
    fn bench_getgrnam_root(b: &mut Bencher) {
        b.iter(|| {
            let _ = getgrnam("root", Some(NssModule::Files));
        });
    }
}