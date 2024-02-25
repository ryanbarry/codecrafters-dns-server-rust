use std::net::UdpSocket;

use bytes::{BufMut, BytesMut};
use nom::{
    bits::{self, complete::tag},
    branch::alt,
    combinator::{map, value},
    number::complete::be_u16,
    sequence::tuple,
    IResult,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
enum Opcode {
    Query = 0,
    Iquery,
    Status,
    #[allow(dead_code)]
    Reserved,
}

impl Opcode {
    fn parser(input: &[u8]) -> IResult<&[u8], Self> {
        bits::bits::<&[u8], Self, nom::error::Error<(&[u8], usize)>, _, _>(alt((
            value(Self::Query, tag(Self::Query as u8, 4usize)),
            value(Self::Iquery, tag(Self::Iquery as u8, 4usize)),
            value(Self::Status, tag(Self::Status as u8, 4usize)),
        )))(input)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
enum Rcode {
    NoError = 0,
    Format,
    Server,
    Name,
    NotImplemented,
    Refused,
    #[allow(dead_code)]
    Reserved,
}

impl Rcode {
    fn parser(input: &[u8]) -> IResult<&[u8], Self> {
        bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(alt((
            value(Self::NoError, tag(Self::NoError as u16, 4usize)),
            value(Self::Format, tag(Self::Format as u16, 4usize)),
            value(Self::Server, tag(Self::Server as u16, 4usize)),
            value(Self::Name, tag(Self::Name as u16, 4usize)),
            value(Self::NotImplemented, tag(Self::Name as u16, 4usize)),
            value(Self::Refused, tag(Self::Refused as u16, 4usize)),
        )))(input)
    }
}

#[derive(Debug)]
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

        let mut fields: u16 = ((self.qr as u16) & 0x0001) << 15;
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

    fn parser(buf: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((
                be_u16,
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(bits::complete::bool),
                Opcode::parser,
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(bits::complete::bool),
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(bits::complete::bool),
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(bits::complete::bool),
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(bits::complete::bool),
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                    bits::complete::take::<&[u8], u8, usize, nom::error::Error<(&[u8], usize)>>(
                        3usize,
                    ),
                ),
                Rcode::parser,
                be_u16,
                be_u16,
                be_u16,
                be_u16,
            )),
            |(id, qr, opcode, aa, tc, rd, ra, _, rcode, qdcount, ancount, nscount, arcount)| Self {
                id,
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                rcode,
                qdcount,
                ancount,
                nscount,
                arcount,
            },
        )(buf)
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
                println!("Received {} bytes from {}\n{:?}", size, source, &buf[..size-1]);

                let req_head = DnsHeader::parser(&buf)
                    .map(|(_, o)| o)
                    .expect("failed parsing request header");

                println!("req_head: {:?}", req_head);

                let res_head = DnsHeader {
                    id: req_head.id,
                    qr: true,
                    opcode: req_head.opcode,
                    aa: false,
                    tc: false,
                    rd: req_head.rd,
                    ra: false,
                    rcode: if req_head.opcode == Opcode::Query {
                        Rcode::NoError
                    } else {
                        Rcode::NotImplemented
                    },
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                };
                println!("res_head: {:?}", res_head);
                let mut response = BytesMut::from(&res_head.serialize()[..]);

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
