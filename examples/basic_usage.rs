use truenas_rust_nss::{getpwnam, getpwuid, getgrnam, getgrgid, getpwall, getgrall, iterpw, itergrp, NssModule};

fn main() {
    println!("=== Rust NSS Library Demo ===\n");

    // Test getpwnam
    println!("Testing getpwnam for 'root':");
    match getpwnam("root", Some(NssModule::Files)) {
        Ok(user) => {
            println!("Found user: {}", user.pw_name);
            println!("UID: {}, GID: {}", user.pw_uid, user.pw_gid);
            println!("Home: {}, Shell: {}", user.pw_dir, user.pw_shell);
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\n{}\n", "=".repeat(50));

    // Test getpwuid
    println!("Testing getpwuid for UID 0:");
    match getpwuid(0, Some(NssModule::Files)) {
        Ok(user) => {
            println!("Found user: {}", user.pw_name);
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\n{}\n", "=".repeat(50));

    // Test getgrnam
    println!("Testing getgrnam for 'root':");
    match getgrnam("root", Some(NssModule::Files)) {
        Ok(group) => {
            println!("Found group: {}", group.gr_name);
            println!("GID: {}", group.gr_gid);
            println!("Members: {:?}", group.gr_mem);
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\n{}\n", "=".repeat(50));

    // Test getgrgid
    println!("Testing getgrgid for GID 0:");
    match getgrgid(0, Some(NssModule::Files)) {
        Ok(group) => {
            println!("Found group: {}", group.gr_name);
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\n{}\n", "=".repeat(50));

    // Test with all modules (None = search all)
    println!("Testing getpwnam for 'root' across all NSS modules:");
    match getpwnam("root", None) {
        Ok(user) => {
            println!("Found user from source: {}", user.source);
            println!("User: {}", user.pw_name);
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\n{}\n", "=".repeat(50));

    // Test iterating through users
    println!("Iterating through first 5 users from FILES module:");
    let mut count = 0;
    for result in iterpw(NssModule::Files) {
        if count >= 5 { break; }
        match result {
            Ok(user) => {
                println!("  {}: {} (UID: {}, GID: {})",
                    count + 1, user.pw_name, user.pw_uid, user.pw_gid);
                count += 1;
            }
            Err(e) => {
                println!("  Error iterating users: {}", e);
                break;
            }
        }
    }

    println!("\n{}\n", "=".repeat(50));

    // Test iterating through groups
    println!("Iterating through first 5 groups from FILES module:");
    count = 0;
    for result in itergrp(NssModule::Files) {
        if count >= 5 { break; }
        match result {
            Ok(group) => {
                println!("  {}: {} (GID: {}, Members: {:?})",
                    count + 1, group.gr_name, group.gr_gid, group.gr_mem);
                count += 1;
            }
            Err(e) => {
                println!("  Error iterating groups: {}", e);
                break;
            }
        }
    }

    println!("\n{}\n", "=".repeat(50));

    // Test getpwall
    println!("Getting all users from FILES module (limited to first 3):");
    match getpwall(Some(NssModule::Files)) {
        Ok(users) => {
            println!("Found {} users total", users.len());
            for (i, user) in users.iter().take(3).enumerate() {
                println!("  {}: {} (UID: {})", i + 1, user.pw_name, user.pw_uid);
            }
            if users.len() > 3 {
                println!("  ... and {} more users", users.len() - 3);
            }
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\n{}\n", "=".repeat(50));

    // Test getgrall
    println!("Getting all groups from FILES module (limited to first 3):");
    match getgrall(Some(NssModule::Files)) {
        Ok(groups) => {
            println!("Found {} groups total", groups.len());
            for (i, group) in groups.iter().take(3).enumerate() {
                println!("  {}: {} (GID: {})", i + 1, group.gr_name, group.gr_gid);
            }
            if groups.len() > 3 {
                println!("  ... and {} more groups", groups.len() - 3);
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}