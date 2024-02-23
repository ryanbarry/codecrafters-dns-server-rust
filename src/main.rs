use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response = [
                    34u8, 12u8, // packet id
                    0b10000000, // QR, OPCODE, AA, TC, RD
                    0b00000000, // RA, Z, RCODE
                    0u8, 0u8,   // QDCOUNT
                    0u8, 0u8,   // ANCOUNT
                    0u8, 0u8,   // NSCOUNT
                    0u8, 0u8,   // ARCOUNT
                ];
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
