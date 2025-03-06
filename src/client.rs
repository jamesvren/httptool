use futures::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::header::ToStrError;
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::fs::OpenOptions;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::task::JoinError;

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("Io: {0}")]
    Io(#[from] std::io::Error),
    #[error("Request: {0}")]
    Request(#[from] reqwest::Error),
    #[error("response not ascii: {0}")]
    ToStrError(#[from] ToStrError),
    #[error("{0}")]
    Error(String),
    #[error(transparent)]
    JoinError(#[from] JoinError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct DownloadState {
    url: String,
    file: String,
    content_length: u64,
    chunks: Vec<ChunkState>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
struct ChunkState {
    start: u64,
    end: u64,
    downloaded: u64,
    completed: bool,
}

pub struct Downloader {
    client: Client,
    max_retries: usize,
    trunk: usize,
    state_file: PathBuf,
    filename: PathBuf,
}

impl Downloader {
    pub fn new(max_retries: usize, timeout: u64) -> Self {
        let client = Client::builder()
            .connection_verbose(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(Duration::from_secs(timeout))
            .read_timeout(Duration::from_secs(timeout))
            .build()
            .unwrap();

        Self {
            client,
            max_retries,
            trunk: 0,
            state_file: PathBuf::new(),
            filename: PathBuf::new(),
        }
    }

    async fn get_content_info(&self, url: &str) -> Result<(bool, u64, String), DownloadError> {
        let response = self.client.head(url).send().await?.error_for_status()?;
        tracing::debug!("Response Header: {:?}", response.headers());

        let content_length: u64 = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| DownloadError::Error("Missing Content-Length header".to_string()))?;

        let resumable = response.headers().contains_key("Accept-Ranges");

        Ok((resumable, content_length, response.url().to_string()))
    }

    pub async fn download_file(
        &mut self,
        url: &str,
        output_path: &str,
        trunk: usize,
    ) -> Result<(), DownloadError> {
        self.filename = output_path.into();
        self.trunk = trunk;
        self.state_file = PathBuf::from(format!("{}.trunk", self.filename.to_str().unwrap()));

        let (resumable, content_length, url) = self.get_content_info(&url).await?;
        tracing::debug!("Final URL: {url}");

        let m = MultiProgress::new();
        let progress_bar = m.add(ProgressBar::new(content_length));
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{msg}{spinner} [{bar:40}] {bytes}/{total_bytes} ({percent}% | {bytes_per_sec}, {eta})")
                .unwrap(),
        );
        //let progress_bar = ProgressBar::new(content_length);
        //progress_bar.set_style(
        //    ProgressStyle::default_bar()
        //       .template("{msg} {spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}% | {bytes_per_sec}, {eta})")
        //       .unwrap()
        //       .progress_chars("#>-"),
        //);

        if resumable {
            progress_bar.set_message("Downloading");
            self.download_chunks(&url, content_length, &progress_bar)
                .await?;
            fs::remove_file(&self.state_file).ok();
        } else {
            println!(
                "Don't support concurrent downloading or trunk size too small, download with single thread"
            );
            progress_bar.set_message("Downloading");
            self.download(&url, &progress_bar).await?;
        };

        progress_bar.finish_with_message("Download completed");
        Ok(())
    }

    fn load_state(&self, url: &str, content_length: u64) -> Result<DownloadState, DownloadError> {
        let file = self.filename.to_str().unwrap().to_string();
        if let Ok(data) = fs::read_to_string(&self.state_file) {
            let state: DownloadState = serde_json::from_str(&data)?;
            if state.file == file && state.content_length == content_length {
                tracing::debug!(
                    "Resume {} tasks to download [len: {content_length}]",
                    self.trunk
                );
                return Ok(state);
            }
        }

        let chunk_size = (content_length as f64 / self.trunk as f64).ceil() as u64;

        tracing::debug!(
            "Start {} tasks to download [len: {content_length}, trunk: {chunk_size}]",
            self.trunk
        );
        let mut chunks = Vec::new();
        let mut start = 0;
        while start < content_length {
            let end = (start + chunk_size - 1).min(content_length - 1);
            chunks.push(ChunkState {
                start,
                end,
                downloaded: 0,
                completed: false,
            });
            start = end + 1;
        }

        Ok(DownloadState {
            url: url.to_string(),
            file,
            content_length,
            chunks,
        })
    }

    async fn save_state(state_file: &PathBuf, state: &DownloadState) -> Result<(), DownloadError> {
        let state_data = serde_json::to_string(state)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            //.append(false)
            .open(state_file)
            .await?;
        file.write_all(state_data.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }

    async fn download(&self, url: &str, progress_bar: &ProgressBar) -> Result<(), DownloadError> {
        let response = self.client.get(url).send().await?.error_for_status()?;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.filename)
            .await?;

        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            progress_bar.inc(chunk.len() as u64);
        }
        file.flush().await?;
        Ok(())
    }

    async fn download_chunks(
        &self,
        url: &str,
        content_length: u64,
        progress_bar: &ProgressBar,
    ) -> Result<(), DownloadError> {
        let state = self.load_state(&url, content_length)?;
        let state_arc = Arc::new(Mutex::new(state));
        let state_for_signal = Arc::clone(&state_arc);

        // handle Control+C
        let state_file = self.state_file.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.unwrap();
            println!("\nCtrl+C received, saving download state...");
            let state = state_for_signal.lock().await;
            println!("    Saving started");
            if let Err(e) = Self::save_state(&state_file, &state).await {
                eprintln!("Failed to save state: {e}");
            }
            std::process::exit(0);
        });

        // handle chunks
        let mut handles = Vec::new();
        let num_chunks = {
            let state = state_arc.lock().await;
            state.chunks.len()
        };
        for i in 0..num_chunks {
            let url = url.to_string();
            let client = self.client.clone();
            let progress_bar = progress_bar.clone();
            let state_arc = Arc::clone(&state_arc);

            let filename = self.filename.clone();
            let state_file = self.state_file.clone();
            let max_retries = self.max_retries;

            handles.push(tokio::spawn(async move {
                let chunk = {
                    let state = state_arc.lock().await;
                    state.chunks[i]
                };

                if chunk.completed {
                    progress_bar.inc(chunk.downloaded);
                    return Ok(());
                }
                let mut retries = 0;

                while retries < max_retries {
                    if let Err(e) = Self::download_chunk(
                        &client,
                        &url,
                        &progress_bar,
                        chunk,
                        &state_arc,
                        i,
                        &filename,
                        &state_file,
                    )
                    .await
                    {
                        retries += 1;
                        println!("Download Error: {e}, retry({retries})...");
                    }
                }
                if retries == max_retries {
                    println!("Error: All retries failed!!!");
                    return Err(DownloadError::Error("Failed to download".to_string()));
                }
                let mut state = state_arc.lock().await;
                state.chunks[i].completed = true;
                Self::save_state(&state_file, &state).await
            }));
        }

        for handle in handles {
            handle.await??
        }
        Ok(())
    }

    async fn download_chunk(
        client: &Client,
        url: &str,
        progress_bar: &ProgressBar,
        chunk: ChunkState,
        state_arc: &Arc<Mutex<DownloadState>>,
        chunk_index: usize,
        filename: &PathBuf,
        state_file: &PathBuf,
    ) -> Result<(), DownloadError> {
        let mut downloaded = chunk.downloaded;
        let range = format!("bytes={}-{}", chunk.start + downloaded, chunk.end);
        tracing::debug!(
            "Downloading trunk [{} - {} :{}]",
            chunk.start,
            chunk.end,
            downloaded
        );
        progress_bar.inc(downloaded);

        let response = client
            .get(url)
            .header("Range", range)
            .send()
            .await?
            .error_for_status()?;

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            //.append(false)
            .open(filename)
            .await?;

        let mut body = response.bytes_stream();
        file.seek(SeekFrom::Start(chunk.start + downloaded)).await?;
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            progress_bar.inc(chunk.len() as u64);

            let mut state = state_arc.lock().await;
            state.chunks[chunk_index].downloaded = downloaded;
            Self::save_state(state_file, &state).await?;
        }
        file.flush().await?;

        Ok(())
    }
}
