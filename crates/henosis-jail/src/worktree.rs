//! Bounded temporary laboratory cloning for non-destructive perturbation runs.
//!
//! Clones regular files and subdirectories from a trusted source project into a
//! fresh temporary directory so perturbation harnesses never modify the user's
//! working tree. Symbolic links, FIFOs, device nodes, excessive nesting, and
//! oversized trees are rejected rather than followed.
//!
//! On filesystems where Rust's `std::fs::copy` uses kernel fast paths (such as
//! `copy_file_range` on Linux or `fclonefileat` on APFS), file contents can be
//! cloned cheaply, falling back cleanly to buffered copy elsewhere. This is
//! workspace isolation against accidental self-mutation, **not** an OS sandbox.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;

/// Resource limits enforced while cloning a laboratory directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloneLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_depth: usize,
}

impl Default for CloneLimits {
    fn default() -> Self {
        Self {
            max_files: 2_048,
            max_total_bytes: 64 * 1024 * 1024,
            max_depth: 16,
        }
    }
}

/// Statistics collected during a laboratory clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloneStats {
    pub files_copied: usize,
    pub dirs_created: usize,
    pub bytes_copied: u64,
}

/// An isolated temporary copy of a project directory, cleaned up on drop.
#[derive(Debug)]
pub struct Worktree {
    tempdir: TempDir,
    stats: CloneStats,
}

impl Worktree {
    /// Clone `source` into a new temporary directory using default limits.
    pub fn clone_from(source: &Path) -> io::Result<Self> {
        Self::clone_with_limits(source, CloneLimits::default())
    }

    /// Clone `source` into a new temporary directory enforcing `limits`.
    pub fn clone_with_limits(source: &Path, limits: CloneLimits) -> io::Result<Self> {
        if !source.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source project must be an absolute path",
            ));
        }
        let root_meta = fs::symlink_metadata(source)?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source project must be a real directory, not a symlink or file",
            ));
        }
        let tempdir = tempfile::tempdir()?;
        let mut stats = CloneStats::default();
        copy_tree(source, tempdir.path(), 0, &limits, &mut stats)?;
        Ok(Self { tempdir, stats })
    }

    pub fn path(&self) -> &Path {
        self.tempdir.path()
    }

    pub fn stats(&self) -> CloneStats {
        self.stats
    }

    /// Resolve a safe relative path inside this worktree, rejecting parent
    /// traversal, absolute components, and any symbolic link along existing
    /// path segments.
    pub fn resolve_relative(&self, relative: &str) -> io::Result<PathBuf> {
        checked_relative_path(self.tempdir.path(), relative)
    }
}

/// Validate `relative` as a strictly local path inside `root` without `..`,
/// absolute prefixes, or existing symlink hops.
pub fn checked_relative_path(root: &Path, relative: &str) -> io::Result<PathBuf> {
    let rel = Path::new(relative);
    if rel.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path must not be empty",
        ));
    }
    let mut current = root.to_path_buf();
    let mut saw_normal = false;
    for component in rel.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                saw_normal = true;
                current.push(part);
                if let Ok(meta) = fs::symlink_metadata(&current) {
                    if meta.file_type().is_symlink() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "symbolic links are rejected inside worktrees",
                        ));
                    }
                }
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path must be relative and must not contain parent traversal",
                ));
            }
        }
    }
    if !saw_normal {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path must name a file inside the worktree",
        ));
    }
    Ok(current)
}

fn copy_tree(
    source: &Path,
    dest: &Path,
    depth: usize,
    limits: &CloneLimits,
    stats: &mut CloneStats,
) -> io::Result<()> {
    if depth > limits.max_depth {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "project directory nesting exceeds worktree depth limit",
        ));
    }
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let src_path = entry.path();
        let meta = fs::symlink_metadata(&src_path)?;
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to clone symlink: {}", src_path.display()),
            ));
        }
        let dst_path = dest.join(entry.file_name());
        if file_type.is_dir() {
            fs::create_dir(&dst_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dst_path, fs::Permissions::from_mode(0o700))?;
            }
            stats.dirs_created += 1;
            copy_tree(&src_path, &dst_path, depth + 1, limits, stats)?;
        } else if file_type.is_file() {
            if stats.files_copied >= limits.max_files {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "project exceeds worktree file count limit",
                ));
            }
            let next_total = stats.bytes_copied.saturating_add(meta.len());
            if next_total > limits.max_total_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "project exceeds worktree total byte limit",
                ));
            }
            let copied = fs::copy(&src_path, &dst_path)?;
            stats.bytes_copied = stats.bytes_copied.saturating_add(copied);
            if stats.bytes_copied > limits.max_total_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "project exceeds worktree total byte limit during copy",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let executable = meta.permissions().mode() & 0o111 != 0;
                let mode = if executable { 0o700 } else { 0o600 };
                fs::set_permissions(&dst_path, fs::Permissions::from_mode(mode))?;
            }
            stats.files_copied += 1;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to clone non-regular entry: {}", src_path.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_nested_project_without_mutating_source_and_enforces_limits() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("input.txt"), b"dt=0.05\n").unwrap();
        fs::write(src.path().join("sub").join("data.csv"), b"1,2,3\n").unwrap();

        let tree = Worktree::clone_from(src.path()).unwrap();
        assert_eq!(tree.stats().files_copied, 2);
        assert_eq!(tree.stats().dirs_created, 1);

        let target = tree.resolve_relative("input.txt").unwrap();
        fs::write(&target, b"dt=0.50\n").unwrap();
        assert_eq!(fs::read(src.path().join("input.txt")).unwrap(), b"dt=0.05\n");
        assert!(tree.resolve_relative("../escape").is_err());
        assert!(tree.resolve_relative("").is_err());
        assert!(tree.resolve_relative(".").is_err());

        let tiny = CloneLimits {
            max_files: 1,
            max_total_bytes: 1024,
            max_depth: 4,
        };
        assert!(Worktree::clone_with_limits(src.path(), tiny).is_err());

        let byte_cap = CloneLimits {
            max_files: 10,
            max_total_bytes: 4,
            max_depth: 4,
        };
        assert!(Worktree::clone_with_limits(src.path(), byte_cap).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_preserves_executable_bit() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let src = tempfile::tempdir().unwrap();
        let bin = src.path().join("run.sh");
        fs::write(&bin, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

        let tree = Worktree::clone_from(src.path()).unwrap();
        let cloned_mode = fs::metadata(tree.path().join("run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(cloned_mode & 0o777, 0o700);

        symlink("run.sh", src.path().join("link")).unwrap();
        assert_eq!(
            Worktree::clone_from(src.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
