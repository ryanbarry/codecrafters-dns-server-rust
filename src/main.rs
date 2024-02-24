use std::net::UdpSocket;

use bytes::{BufMut, BytesMut};

#[derive(Clone, Copy)]
enum Opcode {
    QUERY = 0,
    IQUERY,
    STATUS,
    RESERVED,
}

#[derive(Clone, Copy)]
enum Rcode {
    NO_ERROR = 0,
    FORMAT,
    SERVER,
    NAME,
    NOT_IMPLEMENTED,
    REFUSED,
    RESERVED,
}

struct DnsHeader {
    id: u16,
    qr: bool,
    opcode: Opcode,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    // skipping z for now
    rcode: Rcode,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    fn serialize(&self) -> [u8; 12] {
        let mut buf = BytesMut::with_capacity(12);
        buf.put_u16(self.id);

        let mut fields: u16 = (self.qr as u16) << 15;

        fields |= ((self.opcode as u16) & 0x000F) << 11;

        fields |= ((self.aa as u16) & 0x0001) << 10;
        fields |= ((self.tc as u16) & 0x0001) << 9;
        fields |= ((self.rd as u16) & 0x0001) << 8;
        fields |= ((self.ra as u16) & 0x0001) << 7;
        // skipping Z field
        fields |= (self.rcode as u16) & 0x000F;
        buf.put_u16(fields);

        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);

        let mut res = [0u8; 12];
        res.clone_from_slice(&buf);
        res
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let header = DnsHeader {
                    id: 1234,
                    qr: true,
                    opcode: Opcode::QUERY,
                    aa: false,
                    tc: false,
                    rd: false,
                    ra: false,
                    rcode: Rcode::NO_ERROR,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                };
                let mut response = BytesMut::from(&header.serialize()[..]);

                // Question
                response.put(&b"\x0ccodecrafters\x02io"[..]);
                response.put_u8(0u8); // null byte to end the label sequence that is QNAME

                response.put_u16(1u16); // QTYPE for A record
                response.put_u16(1u16); // QCLASS for IN

                // Answer
                response.put(&b"\x0ccodecrafters\x02io"[..]);
                response.put_u8(0u8);

                response.put_u16(1u16); // TYPE for A record
                response.put_u16(1u16); // CLASS for IN
                response.put_u32(60u32); // TTL
                response.put_u16(4u16); // RDLENGTH
                response.put_slice(&[8u8, 8u8, 8u8, 8u8]); // RDATA corresponding to 8.8.8.8

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
