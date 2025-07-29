use std::time::Instant;
use truenas_rust_nss::{getpwnam, NssModule};

const ITERATIONS: usize = 100_000;
const USERNAME: &str = "root";

fn benchmark_truenas_nss() -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    // Warm up - load the library and cache functions
    let _ = getpwnam(USERNAME, Some(NssModule::Files))?;

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = getpwnam(USERNAME, Some(NssModule::Files))?;
    }
    let duration = start.elapsed();

    Ok(duration)
}

fn benchmark_users_crate() -> std::time::Duration {
    // Warm up
    let _ = users::get_user_by_name(USERNAME);

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = users::get_user_by_name(USERNAME);
    }
    start.elapsed()
}

fn print_results(name: &str, duration: std::time::Duration, emoji: &str) {
    let ns_per_op = duration.as_nanos() / ITERATIONS as u128;
    let ops_per_sec = 1_000_000_000.0 / ns_per_op as f64;

    println!("{} {}:", emoji, name);
    println!("   Total time: {:?}", duration);
    println!("   Time per operation: {} ns", ns_per_op);
    println!("   Operations per second: {:.0}", ops_per_sec);
    println!();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TrueNAS NSS Performance Benchmark ===");
    println!("Testing {} iterations of getpwnam('{}') lookups\n", ITERATIONS, USERNAME);

    // Test TrueNAS NSS Library
    println!("Testing TrueNAS NSS library...");
    let truenas_duration = benchmark_truenas_nss()?;
    print_results("TrueNAS NSS Library", truenas_duration, "🚀");

    // Test Users Crate
    println!("Testing standard users crate...");
    let users_duration = benchmark_users_crate();
    print_results("Users Crate", users_duration, "📚");

    // Performance Comparison
    println!("📊 Performance Comparison:");
    println!();

    let truenas_ns = truenas_duration.as_nanos() / ITERATIONS as u128;
    let users_ns = users_duration.as_nanos() / ITERATIONS as u128;

    let speedup = users_ns as f64 / truenas_ns as f64;
    if speedup > 1.0 {
        println!("🏆 TrueNAS NSS is {:.2}x FASTER than users crate", speedup);
        println!("   Time saved per operation: {} ns", users_ns - truenas_ns);
        println!("   Total time saved for {} operations: {:?}",
                 ITERATIONS,
                 std::time::Duration::from_nanos((users_ns - truenas_ns) as u64 * ITERATIONS as u64));

        let percent_improvement = ((users_ns as f64 - truenas_ns as f64) / users_ns as f64) * 100.0;
        println!("   Performance improvement: {:.1}%", percent_improvement);
    } else {
        println!("📉 TrueNAS NSS is {:.2}x slower than users crate", 1.0 / speedup);
        println!("   Additional time per operation: {} ns", truenas_ns - users_ns);
        let percent_slower = ((truenas_ns as f64 - users_ns as f64) / users_ns as f64) * 100.0;
        println!("   Performance overhead: {:.1}%", percent_slower);
    }

    println!();
    println!("🔍 Analysis:");
    println!("   TrueNAS NSS: Direct NSS calls with cached function pointers");
    println!("   Users crate: Higher-level abstraction using standard libc");
    println!();

    // Test different scenarios
    println!("🧪 Testing different scenarios:");

    // Test multiple modules with TrueNAS
    println!("   Available NSS modules:");
    for module in [NssModule::Files, NssModule::Sss, NssModule::Winbind] {
        print!("     {:?}: ", module);
        match getpwnam(USERNAME, Some(module)) {
            Ok(user) => println!("✅ Found '{}' (UID: {})", user.pw_name, user.pw_uid),
            Err(_) => println!("❌ Not available"),
        }
    }

    // Test user not found performance
    println!();
    println!("⏱️ Testing 'user not found' performance (1000 iterations):");

    let nonexistent_user = "nonexistent_user_12345";
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = getpwnam(nonexistent_user, Some(NssModule::Files));
    }
    let truenas_notfound = start.elapsed();

    let start = Instant::now();
    for _ in 0..1000 {
        let _ = users::get_user_by_name(nonexistent_user);
    }
    let users_notfound = start.elapsed();

    println!("   TrueNAS NSS (not found): {:?} total, {} ns/op",
             truenas_notfound, truenas_notfound.as_nanos() / 1000);
    println!("   Users crate (not found): {:?} total, {} ns/op",
             users_notfound, users_notfound.as_nanos() / 1000);

    println!();
    println!("🧠 Implementation Notes:");
    println!("   TrueNAS NSS: Libraries loaded once, functions cached");
    println!("   Users crate: Uses standard libc getpwnam() - may hit NSS repeatedly");

    Ok(())
}