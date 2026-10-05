use crate::config::IpBanConfig;
use crate::definition_source::{DefinitionDownloader, ReqwestDefinitionDownloader};
use crate::matched_log::MatchedLog;
use abuse_core::IpBanSet;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

const MAX_BYTES: u64 = 16 * 1024 * 1024;

pub struct IpBanState {
    pub config: IpBanConfig,
    pub list: RwLock<Arc<IpBanSet>>,
    pub file: Mutex<Option<File>>,
    pub log: Mutex<Option<MatchedLog>>,
}

impl IpBanState {
    pub fn new(config: IpBanConfig, file: File) -> Self {
        Self {
            config,
            list: RwLock::new(Arc::new(IpBanSet::default())),
            file: Mutex::new(Some(file)),
            log: Mutex::new(None),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.list.read().unwrap().contains(ip)
    }

    pub fn refresh(
        &self,
        downloader: &dyn DefinitionDownloader,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let temp = downloader.download(&self.config.url, &std::env::temp_dir(), MAX_BYTES)?;
        let file = File::open(temp.path())?;
        let list = IpBanSet::parse(BufReader::new(file))?;
        let count = list.len();
        *self.list.write().unwrap() = Arc::new(list);
        Ok(count)
    }

    pub fn fetch(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        self.refresh(&ReqwestDefinitionDownloader::new()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;

    struct Fixture(&'static str);
    impl DefinitionDownloader for Fixture {
        fn download(
            &self,
            _: &str,
            directory: &Path,
            _: u64,
        ) -> Result<NamedTempFile, crate::definition_source::SourceError> {
            let mut temp = NamedTempFile::new_in(directory)?;
            temp.write_all(self.0.as_bytes())?;
            Ok(temp)
        }
    }

    #[test]
    fn refresh_keeps_last_good_snapshot_on_error() {
        let file = tempfile::tempfile().unwrap();
        let state = IpBanState::new(
            IpBanConfig {
                url: "https://example.invalid/list".into(),
                interval: std::time::Duration::from_secs(60),
                log: "test.log".into(),
            },
            file,
        );
        assert_eq!(state.refresh(&Fixture("1.2.3.4 # valid\n")).unwrap(), 1);
        assert!(state.refresh(&Fixture("invalid\n")).is_err());
        assert!(state.contains("1.2.3.4".parse().unwrap()));
    }
}
