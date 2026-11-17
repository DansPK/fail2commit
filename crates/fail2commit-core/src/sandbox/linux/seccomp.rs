//! Classic-BPF deny-list for the Linux sandbox (SPEC-013 §6; FR-020 HB-036, HB-039, HB-060..HB-062).
//!
//! The wrapper applies this program with `setpriv --seccomp-filter <file> --no-new-privs`, which
//! needs the raw `struct sock_filter[]` array (`u16 code, u8 jt, u8 jf, u32 k`, 8 bytes each,
//! native endian). Denied calls return `EPERM`: the package script sees a normal failure, the
//! install reports it, and no core dump of a user process is produced.
//!
//! The program validates the audited architecture first, so a foreign ABI cannot reach the
//! deny-list by syscall number.

/// `BPF_LD | BPF_W | BPF_ABS`
const LD_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`
const JEQ: u16 = 0x15;
/// `BPF_JMP | BPF_JSET | BPF_K`
const JSET: u16 = 0x45;
/// `__X32_SYSCALL_BIT`: x32 syscall numbers must never reach the number-based deny list.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// `BPF_ALU | BPF_AND | BPF_K`
const AND: u16 = 0x54;
/// `BPF_RET | BPF_K`
const RET: u16 = 0x06;

/// `SECCOMP_RET_ERRNO | EPERM`
const RET_EPERM: u32 = 0x0005_0001;
/// `SECCOMP_RET_KILL_PROCESS`
const RET_KILL: u32 = 0x8000_0000;
/// `SECCOMP_RET_ALLOW`
const RET_ALLOW: u32 = 0x7fff_0000;

/// `seccomp_data.nr`
const OFF_NR: u32 = 0;
/// `seccomp_data.arch`
const OFF_ARCH: u32 = 4;
/// `seccomp_data.args[0]`
const OFF_ARG0: u32 = 16;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
const NR_LISTEN: u32 = 50;
#[cfg(target_arch = "aarch64")]
const NR_LISTEN: u32 = 201;
#[cfg(target_arch = "x86_64")]
const NR_SOCKET: u32 = 41;
#[cfg(target_arch = "aarch64")]
const NR_SOCKET: u32 = 198;
#[cfg(target_arch = "x86_64")]
const NR_CLONE: u32 = 56;
#[cfg(target_arch = "aarch64")]
const NR_CLONE: u32 = 220;

/// Namespace bits of `clone(2)`: `CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET`.
const CLONE_NEW_MASK: u32 = 0x7e02_0000;

/// Address families a package may still create: local sockets (already unreachable from the
/// sandbox) and the two internet families the egress path uses.
const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

/// Syscalls refused with `EPERM`, by name and target-arch number.
pub fn denied() -> Vec<(&'static str, u32)> {
    #[cfg(target_arch = "x86_64")]
    let table: &[(&str, u32)] = &[
        ("listen", NR_LISTEN),
        ("mount", 165),
        ("umount2", 166),
        ("swapon", 167),
        ("swapoff", 168),
        ("reboot", 169),
        ("sethostname", 170),
        ("setdomainname", 171),
        ("iopl", 172),
        ("ioperm", 173),
        ("init_module", 175),
        ("delete_module", 176),
        ("get_kernel_syms", 177),
        ("query_module", 178),
        ("quotactl", 179),
        ("nfsservctl", 180),
        ("acct", 163),
        ("settimeofday", 164),
        ("clock_settime", 227),
        ("clock_adjtime", 305),
        ("adjtimex", 159),
        ("syslog", 103),
        ("vhangup", 153),
        ("personality", 135),
        ("ptrace", 101),
        ("process_vm_readv", 310),
        ("process_vm_writev", 311),
        ("bpf", 321),
        ("userfaultfd", 323),
        ("perf_event_open", 298),
        ("keyctl", 250),
        ("add_key", 248),
        ("request_key", 249),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("open_by_handle_at", 304),
        ("name_to_handle_at", 303),
        ("unshare", 272),
        ("setns", 308),
        ("pivot_root", 155),
        ("chroot", 161),
        ("kexec_load", 246),
        ("kexec_file_load", 320),
        ("finit_module", 313),
        ("seccomp", 317),
    ];
    #[cfg(target_arch = "aarch64")]
    let table: &[(&str, u32)] = &[
        ("listen", NR_LISTEN),
        ("mount", 40),
        ("umount2", 39),
        ("swapon", 224),
        ("swapoff", 225),
        ("reboot", 142),
        ("sethostname", 161),
        ("setdomainname", 162),
        ("init_module", 105),
        ("delete_module", 106),
        ("finit_module", 273),
        ("quotactl", 60),
        ("nfsservctl", 42),
        ("acct", 89),
        ("settimeofday", 170),
        ("clock_settime", 112),
        ("clock_adjtime", 266),
        ("adjtimex", 171),
        ("syslog", 116),
        ("vhangup", 58),
        ("personality", 92),
        ("ptrace", 117),
        ("process_vm_readv", 270),
        ("process_vm_writev", 271),
        ("bpf", 280),
        ("userfaultfd", 282),
        ("perf_event_open", 241),
        ("keyctl", 219),
        ("add_key", 217),
        ("request_key", 218),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("open_by_handle_at", 265),
        ("name_to_handle_at", 264),
        ("unshare", 97),
        ("setns", 268),
        ("pivot_root", 41),
        ("chroot", 51),
        ("kexec_load", 104),
        ("kexec_file_load", 294),
        ("seccomp", 277),
    ];
    table.to_vec()
}
/// One `struct sock_filter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

/// The deny-list program as BPF instructions.
fn program() -> Vec<Insn> {
    let denied = denied();
    // arch check (3) + `ld nr` (1) + x32 reject (2) + two instructions per denied call + clone gate and block (5)
    // + socket gate and block (6) + final allow (1).
    let total = 6 + denied.len() * 2 + 5 + 6 + 1;
    let mut p: Vec<Insn> = Vec::with_capacity(total);
    p.push(insn(LD_ABS, 0, 0, OFF_ARCH));
    p.push(insn(JEQ, 1, 0, AUDIT_ARCH));
    p.push(insn(RET, 0, 0, RET_KILL));
    p.push(insn(LD_ABS, 0, 0, OFF_NR));
    // x86_64 also serves x32 numbers (nr | 0x40000000) under the same AUDIT_ARCH; they would
    // bypass every `JEQ nr` below, so kill them before the deny list.
    p.push(insn(JSET, 0, 1, X32_SYSCALL_BIT));
    p.push(insn(RET, 0, 0, RET_KILL));
    for (_, nr) in &denied {
        p.push(insn(JEQ, 0, 1, *nr));
        p.push(insn(RET, 0, 0, RET_EPERM));
    }
    // clone(2) with any namespace flag. The gate matters: without it every syscall would be judged
    // by its first argument, and a pointer there is almost never one of the allowed values.
    p.push(insn(JEQ, 0, 4, NR_CLONE));
    p.push(insn(LD_ABS, 0, 0, OFF_ARG0));
    p.push(insn(AND, 0, 0, CLONE_NEW_MASK));
    // seccomp's verifier accepts JEQ/JGE/JGT/JSET but not JNE, so the test is inverted here.
    p.push(insn(JEQ, 1, 0, 0));
    p.push(insn(RET, 0, 0, RET_EPERM));
    // socket(2) for any family except AF_UNIX, AF_INET and AF_INET6. The block sits next to the
    // final allow so every jump fits in the 8-bit jt field.
    p.push(insn(JEQ, 0, 5, NR_SOCKET));
    let socket_at = p.len();
    let allow_at = socket_at + 5;
    p.push(insn(LD_ABS, 0, 0, OFF_ARG0));
    for (i, family) in [AF_UNIX, AF_INET, AF_INET6].iter().enumerate() {
        let here = socket_at + 1 + i;
        let jt = u8::try_from(allow_at - here - 1).expect("short socket block");
        p.push(insn(JEQ, jt, 0, *family));
    }
    p.push(insn(RET, 0, 0, RET_EPERM));
    p.push(insn(RET, 0, 0, RET_ALLOW));
    debug_assert_eq!(p.len(), total);
    debug_assert_eq!(p.len() - 1, allow_at);
    p
}

fn push_insn(out: &mut Vec<u8>, i: &Insn) {
    out.extend_from_slice(&i.code.to_ne_bytes());
    out.push(i.jt);
    out.push(i.jf);
    out.extend_from_slice(&i.k.to_ne_bytes());
}

/// Serialised filter, exactly what `setpriv --seccomp-filter` expects.
pub fn filter_bytes() -> Vec<u8> {
    let p = program();
    let mut out = Vec::with_capacity(p.len() * 8);
    for i in &p {
        push_insn(&mut out, i);
    }
    out
}

/// Write the filter into `path`: the job's wrapper reads it before any package code runs.
pub fn write_filter(path: &std::path::Path) -> crate::Result<()> {
    std::fs::write(path, filter_bytes())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_validates_arch_and_ends_with_allow() {
        let p = program();
        assert_eq!(p[0], insn(LD_ABS, 0, 0, OFF_ARCH));
        assert_eq!(p[1], insn(JEQ, 1, 0, AUDIT_ARCH));
        assert_eq!(p[2], insn(RET, 0, 0, RET_KILL));
        assert_eq!(p[3], insn(LD_ABS, 0, 0, OFF_NR));
        assert_eq!(p[4], insn(JSET, 0, 1, X32_SYSCALL_BIT));
        assert_eq!(p[5], insn(RET, 0, 0, RET_KILL));
        assert_eq!(p[p.len() - 1], insn(RET, 0, 0, RET_ALLOW));
    }

    /// An x32-numbered syscall (nr | 0x40000000) is killed before any `JEQ nr` can be skipped.
    #[test]
    fn x32_syscall_numbers_are_killed_before_the_deny_list() {
        let p = program();
        let jset = p
            .iter()
            .position(|i| i.code == JSET && i.k == X32_SYSCALL_BIT)
            .expect("x32 check");
        let first_nr_match = p
            .iter()
            .position(|i| i.code == JEQ && i.k != AUDIT_ARCH && i.k != 0);
        assert!(jset < first_nr_match.expect("deny list"));
        // jt = 0 falls into the KILL; jf = 1 skips it.
        assert_eq!((p[jset].jt, p[jset].jf), (0, 1));
        assert_eq!(p[jset + 1], insn(RET, 0, 0, RET_KILL));
    }

    #[test]
    fn every_jump_target_is_inside_the_program() {
        let p = program();
        for (at, i) in p.iter().enumerate() {
            // Only conditional jumps carry a target; RET has jt/jf = 0.
            if i.code != JEQ && i.code != JSET {
                continue;
            }
            for off in [i.jt, i.jf] {
                let target = at as u32 + 1 + u32::from(off);
                assert!(
                    (target as usize) < p.len(),
                    "instruction {at} ({i:?}) jumps past the end"
                );
            }
        }
    }

    #[test]
    fn denied_calls_are_unique_and_bounded() {
        let d = denied();
        let mut names: Vec<&str> = d.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate names");
        let mut nrs: Vec<u32> = d.iter().map(|(_, n)| *n).collect();
        nrs.sort_unstable();
        let count = nrs.len();
        nrs.dedup();
        assert_eq!(nrs.len(), count, "duplicate syscall numbers");
        assert!(d.len() < 100, "filter stays far below BPF_MAXINSNS");
        for want in [
            "mount",
            "unshare",
            "setns",
            "ptrace",
            "bpf",
            "userfaultfd",
            "listen",
        ] {
            assert!(names.contains(&want), "{want} must be denied");
        }
    }

    #[test]
    fn bytes_are_eight_bytes_per_instruction() {
        let p = program();
        assert_eq!(filter_bytes().len(), p.len() * 8);
    }

    /// `setpriv` (what the sandbox wrapper uses) must accept the program, and the denied calls must
    /// fail: check both here so a broken filter fails in `cargo test`, not inside a job.
    #[test]
    fn setpriv_accepts_the_filter_and_denies_its_calls() {
        let setpriv = ["/usr/bin/setpriv", "/bin/setpriv"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(setpriv) = setpriv else {
            eprintln!("SKIP (pending evidence) setpriv is not installed");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("seccomp.bpf");
        write_filter(&file).unwrap();
        let run = |prog: &[&str]| {
            std::process::Command::new(setpriv)
                .arg("--seccomp-filter")
                .arg(&file)
                .arg("--no-new-privs")
                .arg("--")
                .args(prog)
                .output()
                .expect("setpriv runs")
        };
        let ok = run(&["/bin/true"]);
        assert!(
            ok.status.success(),
            "setpriv rejected the filter: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
        // `unshare -U true` needs no privileges, so only the filter can refuse it.
        if std::path::Path::new("/usr/bin/unshare").exists() {
            let denied = run(&["/usr/bin/unshare", "-U", "true"]);
            assert!(
                !denied.status.success(),
                "unshare(CLONE_NEWUSER) was not refused by the filter"
            );
        }
    }
}
