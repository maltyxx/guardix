use crate::core::rulebook::Rulebook;
use anyhow::{Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub struct RulebookStore {
    path: PathBuf,
}

impl RulebookStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create rulebook directory: {:?}", parent))?;
        }

        Ok(Self { path })
    }

    pub async fn load(&self) -> Result<Rulebook> {
        if !self.path.exists() {
            // Create default empty rulebook if it doesn't exist
            let rulebook = Rulebook::default();
            self.save(&rulebook).await?;
            return Ok(rulebook);
        }

        let content = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| format!("Failed to read rulebook file: {:?}", self.path))?;

        let rulebook: Rulebook =
            serde_json::from_str(&content).with_context(|| "Failed to parse rulebook JSON")?;

        Ok(rulebook)
    }

    pub async fn save(&self, rulebook: &Rulebook) -> Result<()> {
        let content = serde_json::to_string_pretty(rulebook)
            .with_context(|| "Failed to serialize rulebook")?;

        tokio::fs::write(&self.path, content)
            .await
            .with_context(|| format!("Failed to write rulebook file: {:?}", self.path))?;

        Ok(())
    }

    pub fn watch(&self) -> Result<mpsc::Receiver<Result<Rulebook>>> {
        let (tx, rx) = mpsc::channel(10);
        let path = self.path.clone();
        let watch_path = if let Some(parent) = path.parent() {
            parent.to_path_buf()
        } else {
            path.clone()
        };

        let file_name = path.file_name().and_then(|n| n.to_str()).map(String::from);

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            runtime.block_on(async move {
                let (notify_tx, mut notify_rx) = mpsc::channel(10);

                let mut watcher = RecommendedWatcher::new(
                    move |res: Result<Event, notify::Error>| {
                        if let Ok(event) = res {
                            let _ = notify_tx.blocking_send(event);
                        }
                    },
                    Config::default(),
                )
                .unwrap();

                watcher
                    .watch(&watch_path, RecursiveMode::NonRecursive)
                    .unwrap();

                while let Some(event) = notify_rx.recv().await {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            // Check if the modified file is our rulebook
                            if let Some(ref name) = file_name {
                                let is_rulebook_event = event.paths.iter().any(|p| {
                                    p.file_name()
                                        .and_then(|n| n.to_str())
                                        .map(|n| n == name)
                                        .unwrap_or(false)
                                });

                                if is_rulebook_event {
                                    // Small delay to ensure file write is complete
                                    tokio::time::sleep(tokio::time::Duration::from_millis(100))
                                        .await;

                                    let store = RulebookStore { path: path.clone() };
                                    let result = store.load().await;
                                    let _ = tx.send(result).await;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            });
        });

        Ok(rx)
    }

    /// Returns the path to the rulebook file - used for debugging and file operations
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rulebook::Rule;
    use crate::models::decision::RuleAction;

    #[tokio::test]
    async fn test_save_and_load() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rulebook_path = temp_dir.path().join("rulebook.json");

        let store = RulebookStore::new(&rulebook_path).unwrap();

        let mut rulebook = Rulebook::new();
        rulebook.add_rule(Rule::new(
            "SELECT.*FROM".to_string(),
            "sqli".to_string(),
            0.8,
            RuleAction::Block,
            "test".to_string(),
        ));

        store.save(&rulebook).await.unwrap();

        let loaded = store.load().await.unwrap();
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].threat_type, "sqli");
    }

    #[tokio::test]
    async fn test_watch_changes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rulebook_path = temp_dir.path().join("rulebook.json");

        let store = RulebookStore::new(&rulebook_path).unwrap();

        // Create initial rulebook
        let rulebook = Rulebook::new();
        store.save(&rulebook).await.unwrap();

        // Start watching
        let mut rx = store.watch().unwrap();

        // Modify the rulebook in a separate task
        let store_clone = RulebookStore::new(&rulebook_path).unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            let mut rulebook = Rulebook::new();
            rulebook.add_rule(Rule::new(
                "test".to_string(),
                "xss".to_string(),
                0.9,
                RuleAction::Flag,
                "test".to_string(),
            ));
            store_clone.save(&rulebook).await.unwrap();
        });

        // Wait for the change notification
        let result = tokio::time::timeout(tokio::time::Duration::from_secs(2), rx.recv()).await;

        assert!(result.is_ok());
        if let Ok(Some(Ok(updated_rulebook))) = result {
            assert_eq!(updated_rulebook.rules.len(), 1);
        }
    }
}
