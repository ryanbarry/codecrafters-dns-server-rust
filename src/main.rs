use std::net::UdpSocket;

use bytes::{BufMut, BytesMut};

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let header = [
                    4u8, 210u8, // packet id
                    0b10000000, // QR, OPCODE, AA, TC, RD
                    0b00000000, // RA, Z, RCODE
                    0u8, 1u8,   // QDCOUNT
                    0u8, 0u8,   // ANCOUNT
                    0u8, 0u8,   // NSCOUNT
                    0u8, 0u8,   // ARCOUNT
                ];
                let mut response = BytesMut::from(&header[..]);

                response.put(&b"\x0ccodecrafters\x02io"[..]);
                response.put_u8(0u8); // null byte to end the label sequence that is QNAME

                response.put_u16(1u16); // QTYPE for A record
                response.put_u16(1u16); // QCLASS for IN

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
