use anyhow::{Result};
use clap::Parser;
use nix::fcntl::OFlag;
use nix::sys::signal::Signal;
use nix::sys::stat::Mode;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;
use std::ffi::CString;
use std::os::unix::prelude::AsFd;
use std::os::unix::prelude::AsRawFd;
use std::os::unix::prelude::FromRawFd;
use std::os::unix::prelude::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::path::Path;
use std::sync::atomic::{Ordering};
use std::sync::Arc;

use rand::distributions::DistString;

mod bpf;
use bpf::SockSkelBuilder;

#[derive(Debug, Parser)]
struct Args {
    /// network interface
    #[arg(short, long)]
    interface: String,


    #[arg(short, long, default_value_os_t=get_current_cgroup())]
    cgroup_base: PathBuf,

    #[arg(trailing_var_arg=true)]
    cmd: Vec<String>,
}


fn get_current_cgroup() -> PathBuf {
    let s = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    PathBuf::from(s.trim_end().split(':').last().unwrap())

}

struct TempCgroup {
    fd: OwnedFd,
    parent_fd: OwnedFd,
    name: String,
}

impl TempCgroup {
    fn create(base_path: &Path, name: &str) -> Result<TempCgroup> {
        let path = PathBuf::from("/sys/fs/cgroup").join(base_path.strip_prefix("/")?);
        let parent_fd = unsafe{OwnedFd::from_raw_fd(nix::fcntl::open(path.as_path(), OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::S_IRWXU)?)};
        nix::sys::stat::mkdirat(parent_fd.as_raw_fd(), name, Mode::S_IRWXU)?;
        let fd = unsafe{ OwnedFd::from_raw_fd(nix::fcntl::openat(parent_fd.as_raw_fd(), name, OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::S_IRWXU)?)};
        Ok(TempCgroup {
            fd,
            parent_fd,
            name: name.to_owned(),
        })
    }
}

impl Drop for TempCgroup {
    fn drop(&mut self) {
        let _ = nix::unistd::unlinkat(Some(self.parent_fd.as_raw_fd()), self.name.as_str(), nix::unistd::UnlinkatFlags::RemoveDir);
    }
}

impl AsFd for TempCgroup {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.fd.as_fd()
    }
}


fn run() -> Result<i32> {
    let running_pid = Arc::new(AtomicI32::new(0));
    {
        let running_pid = running_pid.clone();
        ctrlc::set_handler(move || {
            let p = running_pid.load(Ordering::SeqCst);
            if p > 0 {
                let _ = nix::sys::signal::kill(Pid::from_raw(p), Signal::SIGINT);
            }
        }).unwrap();
    }

    let args = Args::parse();
    let dev_if = nix::net::if_::if_nametoindex(args.interface.as_str())?;

    let mut skel = {
        let mut open_skel = SockSkelBuilder::default().open()?;
        open_skel.rodata().dev_if = dev_if;
        open_skel.load()?
    };

    let cgroup_name = {
        let rand = rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 8);
        format!("{}_{}", args.interface, rand)
    };
    let cgroup = TempCgroup::create(&args.cgroup_base, &cgroup_name)?;
    let _sock_create = skel.progs_mut().sock_create().attach_cgroup(cgroup.as_fd().as_raw_fd())?;
    let _setsockopt = skel.progs_mut().setsockopt().attach_cgroup(cgroup.as_fd().as_raw_fd())?;

    

    let pid = unsafe {
        clone3::Clone3::default()
        // .flag_pidfd(&mut raw_pid_fd)
        .flag_into_cgroup(&cgroup.as_fd().as_raw_fd())
        .call()?
    };

    if pid == 0 {
        let args: Vec<_> = args.cmd.iter().map(|s| CString::new(s.as_bytes()).unwrap()).collect();
        nix::unistd::execvp(&args.first().unwrap(), &args).unwrap();
    } else {
        running_pid.store(pid, Ordering::SeqCst);
        let res = match  nix::sys::wait::waitpid(Some(Pid::from_raw(pid)), Some(WaitPidFlag::__WALL))? {
            nix::sys::wait::WaitStatus::Exited(_, status) => Ok(status),
            nix::sys::wait::WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),

            nix::sys::wait::WaitStatus::Stopped(_, _) => todo!(),
            nix::sys::wait::WaitStatus::PtraceEvent(_, _, _) => todo!(),
            nix::sys::wait::WaitStatus::PtraceSyscall(_) => todo!(),
            nix::sys::wait::WaitStatus::Continued(_) => todo!(),
            nix::sys::wait::WaitStatus::StillAlive => todo!(),
        };
        return res;
    }
    Ok(1)
}

fn main()  {
    match run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        },
    }
}
