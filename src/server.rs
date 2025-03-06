use bytes::Bytes;
use chrono::{DateTime, Local};
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, Result, StatusCode};
use hyper_util::rt::TokioIo;
use mime_guess::from_path;
use multer::Multipart;
use std::path::PathBuf;
use tokio::fs::{self, File, metadata};
//use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;

async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let path = PathBuf::from(".").join(req.uri().path().trim_start_matches('/'));
    match req.method() {
        &Method::GET => handle_get(path).await,
        &Method::POST => handle_post(req, path).await,
        _ => method_not_allowed(),
    }
}

async fn handle_get(path: PathBuf) -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    if path.is_dir() {
        list_directory(path).await
    } else if path.is_file() {
        serve_file(path).await
    } else {
        not_found()
    }
}

/// Format file size into KB, MB, or GB
fn format_file_size(size: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if size < KB {
        format!("{} B", size)
    } else if size < MB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else if size < GB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else {
        format!("{:.2} GB", size as f64 / GB as f64)
    }
}

async fn list_directory(path: PathBuf) -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let mut entries = fs::read_dir(&path).await.unwrap();
    let mut file_list = String::from(
        r#"
        <html>
            <head>
                <style>
                    body {
                        display: flex;
                        font-family: Arial, sans-serif;
                    }
                    .file-list {
                        flex: 1;
                        padding: 20px;
                    }
                    .upload-form {
                        width: 300px;
                        padding: 20px;
                        border-left: 1px solid #ccc;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                    }
                    th, td {
                        padding: 8px;
                        text-align: left;
                        border-bottom: 1px solid #ddd;
                    }
                    th {
                        background-color: #f2f2f2;
                    }
                    progress {
                        width: 100%;
                    }
                    .upload-button {
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        cursor: pointer;
                        margin-top: 10px;
                    }
                    .upload-button:hover {
                        background-color: #45a049;
                    }
                    .file-input {
                        margin-bottom: 10px;
                    }
                </style>
            </head>
            <body>
                <div class="file-list">
                    <h1>Directory Listing</h1>
                    <a href="../">[Up one level]</a>
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Size</th>
                                <th>Bytes</th>
                                <th>Date Modified</th>
                            </tr>
                        </thead>
                        <tbody>
    "#,
    );

    while let Some(entry) = entries.next_entry().await.unwrap() {
        let entry_path = entry.path();
        let entry_name = entry.file_name().to_string_lossy().to_string();
        let metadata = metadata(&entry_path).await.unwrap();
        let modified_time: DateTime<Local> = metadata.modified().unwrap().into();
        let formatted_time = modified_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let file_size = metadata.len();
        let formatted_size = format_file_size(file_size);

        if entry_path.is_dir() {
            file_list.push_str(&format!(
                "<tr><td><a href=\"{}/\">{}/</a></td><td>{}</td><td></td><td>{}</td></tr>",
                entry_name, entry_name, "&#128193;", formatted_time
            ));
        } else {
            file_list.push_str(&format!(
                "<tr><td><a href=\"{}\" download>{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                entry_name, entry_name, formatted_size, file_size, formatted_time
            ));
        }
    }

    file_list.push_str(r#"
                        </tbody>
                    </table>
                </div>
                <div class="upload-form">
                    <h2>Upload File</h2>
                    <form id="uploadForm" method="post" enctype="multipart/form-data">
                        <input type="file" name="file" id="fileInput" class="file-input">
                        <input type="submit" value="Upload" class="upload-button">
                    </form>
                    <div style="margin-top: 10px;">
                        <progress id="progressBar" value="0" max="100" style="width: 100%;"></progress>
                        <span id="progressText">0%</span>
                    </div>
                    <h3>Uploaded Files</h3>
                    <ul id="uploadedFiles"></ul>
                    <script>
                        document.getElementById('uploadForm').onsubmit = function(event) {
                            event.preventDefault();
                            const fileInput = document.getElementById('fileInput');
                            const file = fileInput.files[0];
                            if (!file) return;

                            const formData = new FormData();
                            formData.append('file', file);

                            const xhr = new XMLHttpRequest();
                            let startTime = Date.now(), uploadedBytes = 0;
                            xhr.open('POST', window.location.pathname, true);

                            xhr.upload.onprogress = function(event) {
                                if (event.lengthComputable) {
                                    const percent = (event.loaded / event.total) * 100;
                                    const progressBar = document.getElementById('progressBar');
                                    const progressText = document.getElementById('progressText');

                                    const currentTime = Date.now();
                                    const elapsedTime = (currentTime - startTime) / 1000; // 转换为秒
                                    uploadedBytes += event.loaded - uploadedBytes; // 累计已上传字节
                                    const speedKBps = (uploadedBytes / elapsedTime) / 1024; 
                                    const speedMBps = speedKBps / 1024;
                                    if (speedMBps > 1) {
                                        progressText.innerText = `${percent.toFixed(2)}% / ${speedMBps.toFixed(2)} MB/s`;
                                    } else {
                                        progressText.innerText = `${percent.toFixed(2)}% / ${speedKBps.toFixed(2)} KB/s`;
                                    }
                                    progressBar.value = percent;
                                }
                            };

                            xhr.onload = function() {
                                if (xhr.status === 201) {
                                    document.getElementById('progressText').innerText = 'Upload complete!';
                                    const uploadedFiles = document.getElementById('uploadedFiles');
                                    const listItem = document.createElement('li');
                                    listItem.innerText = `${file.name}  - ${uploadedBytes}`;
                                    uploadedFiles.appendChild(listItem);
                                    setTimeout(() => window.location.reload(), 3000); // Refresh after 3 second
                                } else {
                                    document.getElementById('progressText').innerText = 'Upload failed!';
                                }
                            };

                            xhr.send(formData);
                        };
                    </script>
                </div>
            </body>
        </html>
    "#);

    Ok(Response::new(
        Full::new(Bytes::from(file_list))
            .map_err(|e| match e {})
            .boxed(),
    ))
}

async fn serve_file(path: PathBuf) -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let meta = metadata(&path).await.unwrap();
    let file_size: u64 = meta.len();
    let mime_type = from_path(&path).first_or_octet_stream().to_string();

    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            return match e.kind() {
                std::io::ErrorKind::NotFound => not_found(),
                std::io::ErrorKind::PermissionDenied => forbidden(),
                _ => internal_error(),
            };
        }
    };

    //const BUFFER_SIZE: usize = 8 * 1024; // 8KB 分块
    //// 创建异步流读取器
    //let stream = ReaderStream::with_capacity(file, BUFFER_SIZE);
    //let stream_body = StreamBody::new(stream.map(|result| result.map(|bytes| Frame::data(bytes))));
    let reader_stream = ReaderStream::new(file);
    let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
    let box_body = stream_body.boxed();

    Ok(Response::builder()
        .header("Content-Type", mime_type)
        .header("Content-Length", file_size)
        .header(
            "Content-Disposition",
            format!(
                "attachment; filename=\"{}\"",
                path.file_name().unwrap().to_string_lossy()
            ),
        )
        .status(StatusCode::OK)
        .body(box_body)
        .unwrap())
}

async fn handle_post(
    req: Request<hyper::body::Incoming>,
    path: PathBuf,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    let boundary = req
        .headers()
        .get("content-type")
        .and_then(|ct| ct.to_str().ok())
        .and_then(|ct| multer::parse_boundary(ct).ok())
        .unwrap_or_default();

    let body = req.collect().await?.to_bytes();
    let mut multipart = Multipart::with_reader(body.as_ref(), boundary);

    while let Some(mut field) = multipart.next_field().await.unwrap() {
        let file_name = field
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "uploaded_file".to_string());
        let file_path = path.join(file_name);

        let mut file = File::create(&file_path).await.unwrap();
        while let Some(chunk) = field.chunk().await.unwrap() {
            tokio::io::copy(&mut chunk.as_ref(), &mut file)
                .await
                .unwrap();
        }
    }

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(
            Full::new(Bytes::from("File uploaded successfully"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap())
}

// 错误响应
fn not_found() -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(
            Full::new(Bytes::from("File not found"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap())
}

fn forbidden() -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(
            Full::new(Bytes::from("Access denied"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap())
}

fn method_not_allowed() -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap())
}

fn internal_error() -> Result<Response<BoxBody<Bytes, std::io::Error>>> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(
            Full::new(Bytes::from("Internal server error"))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap())
}

pub async fn server(address: &str) -> std::result::Result<(), Box<dyn std::error::Error>> {
    //let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(address).await?;
    println!("Server started at {address}");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
