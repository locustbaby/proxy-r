use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

fn handle_client(mut client: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 4096];

    // Read and parse the SOCKS5 handshake request
    client.read_exact(&mut buffer[..2])?;
    if buffer[0] != 0x05 {
        // Unsupported SOCKS version
        return Err(io::Error::new(io::ErrorKind::Other, "Unsupported SOCKS version"));
    }

    let num_methods = buffer[1] as usize;
    client.read_exact(&mut buffer[..num_methods])?;
    if !buffer[..num_methods].contains(&0x00) {
        // No supported authentication method found
        return Err(io::Error::new(io::ErrorKind::Other, "No supported authentication method"));
    }

    // Send the selected authentication method (no authentication required)
    client.write_all(&[0x05, 0x00])?;

    // Read and parse the SOCKS5 request for target destination
    client.read_exact(&mut buffer[..4])?;
    if buffer[0] != 0x05 || buffer[1] != 0x01 {
        // Unsupported SOCKS version or command
        return Err(io::Error::new(io::ErrorKind::Other, "Unsupported SOCKS version or command"));
    }

    let addr_type = buffer[3];
    match addr_type {
        0x01 => {
            // IPv4 address
            client.read_exact(&mut buffer[..6])?;
            let target_addr = SocketAddr::from((
                [buffer[0], buffer[1], buffer[2], buffer[3]],
                u16::from_be_bytes([buffer[4], buffer[5]]),
            ));
            println!("Connecting to: {:?}", target_addr);
            let mut target = TcpStream::connect(target_addr)?;

            // Send success response to client
            client.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;

            // Proxy data between client and target
            proxy(&mut client, &mut target)?;
        }
        0x03 => {
            // Domain name
            client.read_exact(&mut buffer[..1])?;
            let domain_length = buffer[0] as usize;
            client.read_exact(&mut buffer[..domain_length + 2])?;
            let domain_name = String::from_utf8_lossy(&buffer[..domain_length]);
            let port = u16::from_be_bytes([buffer[domain_length], buffer[domain_length + 1]]);
            let target_addr = format!("{}:{}", domain_name, port);
            println!("Connecting to: {}", target_addr);
            let mut target = TcpStream::connect(target_addr)?;

            // Send success response to client
            client.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;

            // Proxy data between client and target
            proxy(&mut client, &mut target)?;
        }
        _ => {
            // Unsupported address type
            return Err(io::Error::new(io::ErrorKind::Other, "Unsupported address type"));
        }
    }

    Ok(())
}

fn proxy(src: &mut TcpStream, dst: &mut TcpStream) -> io::Result<()> {
    let mut buffer = [0; 4096];
    loop {
        let bytes_read = src.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(());
        }
        dst.write_all(&buffer[..bytes_read])?;

        let bytes_written = dst.read(&mut buffer)?;
        if bytes_written == 0 {
            return Ok(());
        }
        src.write_all(&buffer[..bytes_written])?;
    }
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:1080")?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || {
                    if let Err(err) = handle_client(stream) {
                        eprintln!("Error: {}", err);
                    }
                });
            }
            Err(err) => {
                eprintln!("Error accepting connection: {}", err);
            }
        }
    }

    Ok(())
}