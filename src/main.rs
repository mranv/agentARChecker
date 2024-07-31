use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

// Constants
const COMPONENT: &str = "com";
const CONFIGURATION: &str = "active-response";
const GETCONFIG_COMMAND: &str = "getconfig";
const DEST_SOCKET: &str = "/var/ossec/queue/sockets/remote";
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_ATTEMPTS: u32 = 3;

// Custom error type
#[derive(Debug)]
struct ShowError(String);

impl fmt::Display for ShowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ShowError: {}", self.0)
    }
}

impl From<io::Error> for ShowError {
    fn from(error: io::Error) -> Self {
        ShowError(error.to_string())
    }
}

impl From<std::string::FromUtf8Error> for ShowError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        ShowError(error.to_string())
    }
}

// Socket wrapper
struct SocketInstance {
    stream: Option<UnixStream>,
    path: String,
}

impl SocketInstance {
    fn new(path: &str) -> Result<Self, ShowError> {
        let mut instance = SocketInstance {
            stream: None,
            path: path.to_string(),
        };
        instance.connect()?;
        Ok(instance)
    }

    fn connect(&mut self) -> Result<(), ShowError> {
        self.stream = Some(UnixStream::connect(&self.path)?);
        Ok(())
    }

    fn send(&mut self, msg: &[u8]) -> Result<(), ShowError> {
        let stream = self.stream.as_mut().ok_or(ShowError("Socket not connected".into()))?;
        let header = (msg.len() as u32).to_le_bytes();
        stream.write_all(&header)?;
        stream.write_all(msg)?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Vec<u8>, ShowError> {
        let stream = self.stream.as_mut().ok_or(ShowError("Socket not connected".into()))?;
        let mut header = [0; 4];
        stream.read_exact(&mut header)?;
        let size = u32::from_le_bytes(header) as usize;
        let mut buffer = vec![0; size];
        stream.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

impl Drop for SocketInstance {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

// Process a single agent
fn process_agent(agent_id: &str) -> Result<String, ShowError> {
    let mut socket = SocketInstance::new(DEST_SOCKET)?;
    println!("Connected to socket for agent {}: {}", agent_id, DEST_SOCKET);

    let msg = format!("{} {} {} {}", agent_id, COMPONENT, GETCONFIG_COMMAND, CONFIGURATION);
    println!("Agent {}: Encoded MSG: {:?}", agent_id, msg.as_bytes());

    socket.send(msg.as_bytes())?;
    println!("Message sent to agent {}", agent_id);

    let rec_msg_bytes = socket.receive()?;
    let rec_msg = String::from_utf8(rec_msg_bytes)?;
    let mut parts = rec_msg.splitn(2, ' ');
    let rec_msg_ok = parts.next().unwrap_or("");
    let rec_msg_body = parts.next().unwrap_or("");

    if rec_msg_ok == "err" && rec_msg_body.contains("Cannot send request") {
        return Err(ShowError("Agent is not connected".into()));
    }

    Ok(format!("rec_msg_ok: {} | rec_msg_body: {}", rec_msg_ok, rec_msg_body))
}

fn main() -> io::Result<()> {
    println!("Enter agent IDs (one per line). Press Ctrl+D (Unix) or Ctrl+Z (Windows) when finished:");
    
    let agent_ids: Vec<String> = io::stdin().lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .collect();

    for agent_id in agent_ids {
        let mut attempts = 0;

        while attempts < MAX_ATTEMPTS {
            match process_agent(&agent_id) {
                Ok(response) => {
                    println!("Message received from agent {}", agent_id);
                    println!("{}", response);
                    break;
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        eprintln!("Error processing agent {}: {}", agent_id, e);
                    } else {
                        eprintln!("Attempt {} failed for agent {}: {}. Retrying...", attempts, agent_id, e);
                        thread::sleep(RECONNECT_DELAY);
                    }
                }
            }
        }
    }

    Ok(())
}