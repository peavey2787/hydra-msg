use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::StegoError;

use super::protocol::{parse_response, Response};

pub(super) const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROGRESS_RECORDS: usize = 10_000;

type ReadResult = Result<Vec<u8>, String>;
type WriteResult = Result<(), String>;

struct WriteRequest {
    bytes: Vec<u8>,
    acknowledgement: SyncSender<WriteResult>,
}

pub(super) struct ProcessIo {
    child: Child,
    requests: Option<SyncSender<WriteRequest>>,
    responses: Option<Receiver<ReadResult>>,
    writer: Option<JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
    terminated: bool,
}

impl ProcessIo {
    pub(super) fn new(child: Child, stdin: ChildStdin, stdout: ChildStdout) -> Self {
        let (request_sender, request_receiver) = mpsc::sync_channel::<WriteRequest>(1);
        let writer = thread::spawn(move || write_requests(stdin, request_receiver));
        let (sender, responses) = mpsc::sync_channel(8);
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_bounded_line(&mut reader) {
                    Ok(Some(line)) => {
                        if sender.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            }
        });
        Self {
            child,
            requests: Some(request_sender),
            responses: Some(responses),
            writer: Some(writer),
            reader: Some(reader),
            terminated: false,
        }
    }

    pub(super) fn request(
        &mut self,
        request: &str,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<String, StegoError> {
        self.request_with_progress(request, timeout, operation, &mut |_, _| {})
    }

    pub(super) fn request_with_progress<F>(
        &mut self,
        request: &str,
        timeout: Duration,
        operation: &'static str,
        on_progress: &mut F,
    ) -> Result<String, StegoError>
    where
        F: FnMut(u8, &str),
    {
        if self.terminated {
            return Err(StegoError::Model(
                "model process is not available".to_owned(),
            ));
        }
        let request_bytes = prepare_request(request)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(StegoError::InvalidConfig("model timeout overflow"))?;
        let written = self.enqueue_request(request_bytes)?;
        self.await_write(written, deadline, operation)?;

        for _ in 0..MAX_PROGRESS_RECORDS {
            let line = self.next_response_line(deadline, operation)?;
            match parse_response(&line).inspect_err(|_| self.terminate())? {
                Response::Progress(percent, message) => on_progress(percent, &message),
                Response::Ok(value) => return Ok(value),
                Response::Error(error) => return Err(StegoError::Model(error)),
            }
        }
        self.terminate();
        Err(StegoError::Model(
            "model returned too many progress records".to_owned(),
        ))
    }

    fn enqueue_request(&mut self, bytes: Vec<u8>) -> Result<Receiver<WriteResult>, StegoError> {
        let (acknowledgement, written) = mpsc::sync_channel(1);
        let request = WriteRequest {
            bytes,
            acknowledgement,
        };
        if self
            .requests
            .as_ref()
            .expect("live process keeps its request channel")
            .send(request)
            .is_err()
        {
            self.terminate();
            return Err(StegoError::Model(
                "model process writer is not available".to_owned(),
            ));
        }
        Ok(written)
    }

    fn await_write(
        &mut self,
        written: Receiver<WriteResult>,
        deadline: Instant,
        operation: &'static str,
    ) -> Result<(), StegoError> {
        let remaining = self.remaining_time(deadline, operation)?;
        match written.recv_timeout(remaining) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.terminate();
                Err(StegoError::Model(error))
            }
            Err(RecvTimeoutError::Timeout) => self.timeout(operation),
            Err(RecvTimeoutError::Disconnected) => {
                self.terminate();
                Err(StegoError::Model(
                    "model process writer stopped unexpectedly".to_owned(),
                ))
            }
        }
    }

    fn next_response_line(
        &mut self,
        deadline: Instant,
        operation: &'static str,
    ) -> Result<Vec<u8>, StegoError> {
        let remaining = self.remaining_time(deadline, operation)?;
        match self
            .responses
            .as_ref()
            .expect("live process keeps its response channel")
            .recv_timeout(remaining)
        {
            Ok(Ok(line)) => Ok(line),
            Ok(Err(error)) => {
                self.terminate();
                Err(StegoError::Model(error))
            }
            Err(RecvTimeoutError::Timeout) => self.timeout(operation),
            Err(RecvTimeoutError::Disconnected) => {
                let status = self.child.try_wait().ok().flatten();
                self.terminate();
                Err(StegoError::Model(format!(
                    "model process closed its output{}",
                    status.map_or_else(String::new, |status| format!(" ({status})"))
                )))
            }
        }
    }

    fn remaining_time(
        &mut self,
        deadline: Instant,
        operation: &'static str,
    ) -> Result<Duration, StegoError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return self.timeout(operation);
        }
        Ok(remaining)
    }

    fn timeout<T>(&mut self, operation: &'static str) -> Result<T, StegoError> {
        self.terminate();
        Err(StegoError::Model(format!("{operation} timed out")))
    }

    pub(super) fn terminate(&mut self) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        self.requests.take();
        self.responses.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for ProcessIo {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn prepare_request(request: &str) -> Result<Vec<u8>, StegoError> {
    let wire_len = request
        .len()
        .checked_add(1)
        .ok_or_else(|| StegoError::Model("model request size overflow".to_owned()))?;
    if wire_len > MAX_REQUEST_BYTES {
        return Err(StegoError::Model(
            "model request exceeded the 16 MiB limit".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(wire_len);
    bytes.extend_from_slice(request.as_bytes());
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_requests(mut stdin: ChildStdin, requests: Receiver<WriteRequest>) {
    while let Ok(request) = requests.recv() {
        let result = stdin
            .write_all(&request.bytes)
            .and_then(|()| stdin.flush())
            .map_err(|error| format!("write model request: {error}"));
        let failed = result.is_err();
        let _ = request.acknowledgement.send(result);
        if failed {
            break;
        }
    }
}

fn read_bounded_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| format!("read model response: {error}"))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_RESPONSE_BYTES {
            return Err("model response exceeded the 16 MiB limit".to_owned());
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_framing_is_bounded_including_newline() {
        assert_eq!(prepare_request("ok").unwrap(), b"ok\n");
        let oversized = "x".repeat(MAX_REQUEST_BYTES);
        assert!(prepare_request(&oversized)
            .unwrap_err()
            .to_string()
            .contains("16 MiB"));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_covers_a_child_blocked_on_stdin() {
        use std::process::{Command, Stdio};

        let mut child = Command::new("sh")
            .args(["-c", "while :; do :; done"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut io = ProcessIo::new(child, stdin, stdout);
        let request = "x".repeat(1024 * 1024);
        let started = Instant::now();
        let error = io
            .request(&request, Duration::from_millis(100), "test inference")
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn bounded_line_reader_accepts_eof_and_rejects_oversize() {
        let mut normal = Cursor::new(b"ok\tvalue\nnext".as_slice());
        assert_eq!(
            read_bounded_line(&mut normal).unwrap().unwrap(),
            b"ok\tvalue\n"
        );
        assert_eq!(read_bounded_line(&mut normal).unwrap().unwrap(), b"next");

        let oversized = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let mut oversized = Cursor::new(oversized);
        assert!(read_bounded_line(&mut oversized)
            .unwrap_err()
            .contains("16 MiB"));
    }
}
