//! Client-under-test CLI for the TUF conformance suite (PLAN.md D1 mitigation).
//!
//! D1 requires spec conformance to be *measured* rather than assumed, which
//! matters more than usual here: we ship a forked `tuf` crate carrying four
//! changes to its verification behaviour, one of them a security fix (§5.5).
//! This binary lets the official suite exercise that fork directly.
//!
//! It implements the protocol in the suite's `CLIENT-CLI.md`:
//!
//! ```text
//! dist-conformance --metadata-dir DIR init TRUSTED_ROOT
//! dist-conformance --metadata-dir DIR --metadata-url URL refresh
//! dist-conformance --metadata-dir DIR --metadata-url URL \
//!     --target-name PATH --target-base-url URL --target-dir DIR download
//! ```
//!
//! Exit code 0 on complete success, 1 on any failure. This is a test tool and
//! is never shipped to users.

use std::collections::HashMap;
use std::fs;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::ExitCode;

use futures_executor::block_on;
use futures_util::future::{BoxFuture, FutureExt as _};
use futures_util::io::{AsyncRead, AsyncReadExt as _, Cursor};
use tuf::Error;
use tuf::client::{Client, Config};
use tuf::interchange::Json;
use tuf::metadata::{MetadataPath, MetadataVersion, RawSignedMetadata, TargetPath};
use tuf::repository::{FileSystemRepositoryBuilder, RepositoryProvider};

/// Distinguishes a missing file from a genuine failure. The distinction is
/// load-bearing: the root rotation loop probes for the next root version and
/// stops on not-found.
enum FetchError {
    NotFound,
    Other(String),
}

/// Remote repository over plain HTTP.
struct HttpProvider {
    base: String,
}

impl HttpProvider {
    fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
        }
    }

    fn get(url: String) -> Result<Box<dyn AsyncRead + Send + Unpin>, FetchError> {
        match ureq::get(&url).call() {
            Ok(response) => {
                let mut buf = Vec::new();
                response
                    .into_reader()
                    .read_to_end(&mut buf)
                    .map_err(|e| FetchError::Other(e.to_string()))?;
                Ok(Box::new(Cursor::new(buf)))
            }
            Err(ureq::Error::Status(404, _)) => Err(FetchError::NotFound),
            Err(e) => Err(FetchError::Other(e.to_string())),
        }
    }
}

impl RepositoryProvider<Json> for HttpProvider {
    fn fetch_metadata<'a>(
        &'a self,
        meta_path: &MetadataPath,
        version: MetadataVersion,
    ) -> BoxFuture<'a, tuf::Result<Box<dyn AsyncRead + Send + Unpin + 'a>>> {
        let url = format!(
            "{}/{}",
            self.base,
            meta_path.components::<Json>(version).join("/")
        );
        let path = meta_path.clone();

        async move {
            match HttpProvider::get(url) {
                Ok(reader) => Ok(reader),
                // The root rotation loop probes for the next root version and
                // relies on this exact variant to know when to stop. Mapping a
                // 404 to anything else turns a normal refresh into a failure.
                Err(FetchError::NotFound) => Err(Error::MetadataNotFound { path, version }),
                Err(FetchError::Other(e)) => Err(Error::Opaque(e)),
            }
        }
        .boxed()
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &TargetPath,
    ) -> BoxFuture<'a, tuf::Result<Box<dyn AsyncRead + Send + Unpin + 'a>>> {
        let url = format!("{}/{}", self.base, target_path.components().join("/"));
        let path = target_path.clone();

        async move {
            match HttpProvider::get(url) {
                Ok(reader) => Ok(reader),
                Err(FetchError::NotFound) => Err(Error::TargetNotFound(path)),
                Err(FetchError::Other(e)) => Err(Error::Opaque(e)),
            }
        }
        .boxed()
    }
}

/// Flags may appear before the subcommand, so parse positionally-agnostically.
struct Args {
    flags: HashMap<String, String>,
    command: String,
    positional: Vec<String>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut flags = HashMap::new();
        let mut command = String::new();
        let mut positional = Vec::new();

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "-v" || arg == "--verbose" {
                continue;
            }
            if let Some(name) = arg.strip_prefix("--") {
                let value = args
                    .next()
                    .ok_or_else(|| format!("--{name} requires a value"))?;
                flags.insert(name.to_owned(), value);
            } else if command.is_empty() {
                command = arg;
            } else {
                positional.push(arg);
            }
        }

        if command.is_empty() {
            return Err("no subcommand given".to_owned());
        }
        Ok(Self {
            flags,
            command,
            positional,
        })
    }

    fn flag(&self, name: &str) -> Result<&str, String> {
        self.flags
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("--{name} is required for `{}`", self.command))
    }
}

type Cut = Client<Json, tuf::repository::FileSystemRepository<Json>, HttpProvider>;

/// Build a client whose trust anchor is the root already in `metadata-dir`.
///
/// The protocol stores metadata under unversioned names, so the local root is
/// read directly rather than through the crate's `with_trusted_local`, which
/// looks for `1.root.json`.
fn client(metadata_dir: &str, metadata_url: &str) -> Result<Cut, String> {
    let root_path = PathBuf::from(metadata_dir).join("root.json");
    let root_bytes = fs::read(&root_path).map_err(|e| format!("reading {root_path:?}: {e}"))?;
    let trusted_root: RawSignedMetadata<Json, _> = RawSignedMetadata::new(root_bytes);

    let local = FileSystemRepositoryBuilder::<Json>::new(PathBuf::from(metadata_dir))
        .build()
        .map_err(|e| format!("opening local repository: {e}"))?;

    block_on(Client::with_trusted_root(
        Config::default(),
        &trusted_root,
        local,
        HttpProvider::new(metadata_url),
    ))
    .map_err(|e| format!("initialising client: {e}"))
}

fn init(args: &Args) -> Result<(), String> {
    let metadata_dir = args.flag("metadata-dir")?;
    let trusted_root = args
        .positional
        .first()
        .ok_or("init requires a trusted root path")?;

    fs::create_dir_all(metadata_dir).map_err(|e| format!("creating {metadata_dir}: {e}"))?;
    fs::copy(trusted_root, PathBuf::from(metadata_dir).join("root.json"))
        .map_err(|e| format!("copying trusted root: {e}"))?;
    Ok(())
}

fn refresh(args: &Args) -> Result<(), String> {
    let mut client = client(args.flag("metadata-dir")?, args.flag("metadata-url")?)?;
    block_on(client.update()).map_err(|e| format!("refresh failed: {e}"))?;
    Ok(())
}

fn download(args: &Args) -> Result<(), String> {
    let mut client = client(args.flag("metadata-dir")?, args.flag("metadata-url")?)?;
    block_on(client.update()).map_err(|e| format!("refresh failed: {e}"))?;

    let target_name = args.flag("target-name")?;
    let target_dir = args.flag("target-dir")?;
    let target =
        TargetPath::new(target_name.to_owned()).map_err(|e| format!("invalid target path: {e}"))?;

    *client.remote_repo_mut() = HttpProvider::new(args.flag("target-base-url")?);

    let mut bytes = Vec::new();
    {
        let mut reader =
            block_on(client.fetch_target(&target)).map_err(|e| format!("fetch failed: {e}"))?;
        // The crate verifies length and hashes as the stream is consumed, and
        // only reports success once every byte has been read, so nothing here
        // may be written out before this returns Ok.
        block_on(reader.read_to_end(&mut bytes)).map_err(|e| format!("read failed: {e}"))?;
    }

    fs::create_dir_all(target_dir).map_err(|e| format!("creating {target_dir}: {e}"))?;
    let name = target.components().join("_").replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-',
        "_",
    );
    fs::write(PathBuf::from(target_dir).join(name), &bytes)
        .map_err(|e| format!("writing artifact: {e}"))?;
    Ok(())
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    match args.command.as_str() {
        "init" => init(&args),
        "refresh" => refresh(&args),
        "download" => download(&args),
        other => Err(format!("unknown subcommand `{other}`")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("dist-conformance: {message}");
            ExitCode::FAILURE
        }
    }
}
