use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const AGENT_ID: &str = "003";
const COMPONENT: &str = "com";
const CONFIGURATION: &str = "active-response";
const GETCONFIG_COMMAND: &str = "getconfig";
const DEST_SOCKET: &str = "/var/ossec/queue/sockets/remote";

#[derive(Debug)]
struct ShowError {
    message: String,
}

impl fmt::Display for ShowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ShowError: {}", self.message)
    }
}

impl ShowError {
    fn new(message: &str) -> Self {
        ShowError {
            message: message.to_string(),
        }
    }
}

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
        UnixStream::connect(&self.path)
            .map(|stream| self.stream = Some(stream))
            .map_err(|err| ShowError::new(&format!("Connection error: {}", err)))
    }

    fn send(&mut self, msg_bytes: &[u8]) -> Result<usize, ShowError> {
        if let Some(ref mut stream) = self.stream {
            let header = (msg_bytes.len() as u32).to_le_bytes();
            stream.write_all(&header)
                .map_err(|e| ShowError::new(&format!("Write error: {}", e)))?;
            let sent = stream.write(msg_bytes)
                .map_err(|e| ShowError::new(&format!("Write error: {}", e)))?;
            if sent == 0 {
                Err(ShowError::new("Number of sent bytes is 0"))
            } else {
                Ok(sent)
            }
        } else {
            Err(ShowError::new("Socket is not connected"))
        }
    }

    fn receive(&mut self) -> Result<Vec<u8>, ShowError> {
        if let Some(ref mut stream) = self.stream {
            let mut header = [0; 4];
            stream.read_exact(&mut header)
                .map_err(|e| ShowError::new(&format!("Read error: {}", e)))?;
            let size = u32::from_le_bytes(header) as usize;

            let mut buffer = vec![0; size];
            stream.read_exact(&mut buffer)
                .map_err(|e| ShowError::new(&format!("Read error: {}", e)))?;
            Ok(buffer)
        } else {
            Err(ShowError::new("Socket is not connected"))
        }
    }
}

impl Drop for SocketInstance {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn main() {
    let msg = format!(
        "{:03} {} {} {}",
        AGENT_ID, COMPONENT, GETCONFIG_COMMAND, CONFIGURATION
    );

    println!("Encoded MSG: {:?}", msg.as_bytes());

    // Socket connection
    let mut socket = match SocketInstance::new(DEST_SOCKET) {
        Ok(sock) => sock,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };
    
    println!("Connected to the socket: {}", DEST_SOCKET);

    // Send message
    if let Err(e) = socket.send(msg.as_bytes()) {
        eprintln!("Send error: {}", e);
    } else {
        println!("Message sent to the agent");
    }

    // Receive response
    match socket.receive() {
        Ok(rec_msg_bytes) => {
            let rec_msg = String::from_utf8_lossy(&rec_msg_bytes);
            let mut parts = rec_msg.splitn(2, ' ');
            let rec_msg_ok = parts.next().unwrap_or("");
            let rec_msg_body = parts.next().unwrap_or("");
            println!("Message received from the agent");
            println!("rec_msg_ok: {} | rec_msg_body: {}", rec_msg_ok, rec_msg_body);
        }
        Err(e) => eprintln!("Receive error: {}", e),
    }
}
