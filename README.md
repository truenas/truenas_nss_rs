# TrueNAS Rust NSS Library

A Rust library for interfacing with Name Service Switch (NSS) modules to query user and group information from various sources including files, LDAP, SSS, and Winbind.

## Features

- **User lookups**: Query users by name (`getpwnam`) or UID (`getpwuid`)
- **Group lookups**: Query groups by name (`getgrnam`) or GID (`getgrgid`)
- **Iteration**: Stream through users (`iterpw`) and groups (`itergrp`)
- **Bulk operations**: Get all users (`getpwall`) or groups (`getgrall`)
- **JSON serialization**: Convert entries to JSON using serde
- **Multiple NSS modules**: Support for FILES, SSS, and WINBIND modules
- **Thread-safe**: Proper cleanup and memory management
- **Error handling**: Comprehensive error types with NSS return codes

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
truenas_rust_nss = "0.1.0"
```

### Basic Examples

```rust
use truenas_rust_nss::{getpwnam, getgrnam, NssModule};

// Get user by name from FILES module
match getpwnam("root", Some(NssModule::Files)) {
    Ok(user) => {
        println!("User: {} (UID: {})", user.pw_name, user.pw_uid);
        println!("JSON: {}", user.to_json().unwrap());
    }
    Err(e) => eprintln!("Error: {}", e),
}

// Get group by name, search all modules
match getgrnam("wheel", None) {
    Ok(group) => {
        println!("Group: {} (GID: {})", group.gr_name, group.gr_gid);
        println!("Members: {:?}", group.gr_mem);
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

### Iteration Examples

```rust
use truenas_rust_nss::{iterpw, itergrp, NssModule};

// Iterate through users
for result in iterpw(NssModule::Files) {
    match result {
        Ok(user) => println!("User: {}", user.pw_name),
        Err(e) => {
            eprintln!("Error: {}", e);
            break;
        }
    }
}

// Iterate through groups
for result in itergrp(NssModule::Files) {
    match result {
        Ok(group) => println!("Group: {}", group.gr_name),
        Err(e) => {
            eprintln!("Error: {}", e);
            break;
        }
    }
}
```

## Testing

Run unit tests:
```bash
cargo test
```

Run integration tests (requires system NSS libraries):
```bash
cargo test --ignored
```

Run specific test:
```bash
cargo test test_passwd_entry_json_serialization
```

## NSS Module Support

- **FILES**: `/etc/passwd` and `/etc/group` files
- **SSS**: System Security Services Daemon
- **WINBIND**: Samba Winbind for Active Directory

## Error Handling

The library uses comprehensive error types:

- `NssOperationFailed`: NSS function call failed
- `BufferTooSmall`: Internal buffer needs expansion
- `InvalidUtf8`: String conversion error
- `NullPointer`: Null pointer encountered
- `LibraryError`: Failed to load NSS library

## Thread Safety

The library handles NSS module threading restrictions:
- Iterators properly initialize and cleanup NSS state
- No concurrent iterators for same module/database
- Automatic resource cleanup via Drop trait

## Requirements

- Linux system with NSS libraries
- Standard NSS modules (`libnss_files.so.2`, etc.)
- Rust 2021 edition

## License

GPL-3.0