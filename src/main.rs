use std::net::UdpSocket;

use bytes::{BufMut, BytesMut};
use nom::{
    bits,
    branch::alt,
    combinator::{map, map_res, value, verify, into},
    number::complete::{be_u16, u8},
    sequence::tuple,
    IResult, Finish, AsBytes, multi::{length_data, many_till}, complete::tag,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
enum Opcode {
    Query = 0,
    Iquery,
    Status,
    Reserved3,
    Reserved4,
    Reserved5,
    Reserved6,
    Reserved7,
    Reserved8,
    Reserved9,
    Reserved10,
    Reserved11,
    Reserved12,
    Reserved13,
    Reserved14,
    Reserved15,
}

impl Opcode {
    fn parser(input: (&[u8], usize)) -> IResult<(&[u8], usize), Self> {
        alt((
            value(Self::Query, bits::complete::tag(Self::Query as u8, 4usize)),
            value(
                Self::Iquery,
                bits::complete::tag(Self::Iquery as u8, 4usize),
            ),
            value(
                Self::Status,
                bits::complete::tag(Self::Status as u8, 4usize),
            ),
            value(Self::Reserved3, bits::complete::tag(Self::Reserved3 as u8, 4usize)),
            value(Self::Reserved4, bits::complete::tag(Self::Reserved4 as u8, 4usize)),
            value(Self::Reserved5, bits::complete::tag(Self::Reserved5 as u8, 4usize)),
            value(Self::Reserved6, bits::complete::tag(Self::Reserved6 as u8, 4usize)),
            value(Self::Reserved7, bits::complete::tag(Self::Reserved7 as u8, 4usize)),
            value(Self::Reserved8, bits::complete::tag(Self::Reserved8 as u8, 4usize)),
            value(Self::Reserved9, bits::complete::tag(Self::Reserved9 as u8, 4usize)),
            value(Self::Reserved10, bits::complete::tag(Self::Reserved10 as u8, 4usize)),
            value(Self::Reserved11, bits::complete::tag(Self::Reserved11 as u8, 4usize)),
            value(Self::Reserved12, bits::complete::tag(Self::Reserved12 as u8, 4usize)),
            value(Self::Reserved13, bits::complete::tag(Self::Reserved13 as u8, 4usize)),
            value(Self::Reserved14, bits::complete::tag(Self::Reserved14 as u8, 4usize)),
            value(Self::Reserved15, bits::complete::tag(Self::Reserved15 as u8, 4usize)),
        ))(input)
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
    Reserved6,
    Reserved7,
    Reserved8,
    Reserved9,
    Reserved10,
    Reserved11,
    Reserved12,
    Reserved13,
    Reserved14,
    Reserved15,
}

impl Rcode {
    fn parser(input: (&[u8], usize)) -> IResult<(&[u8], usize), Self> {
        alt((
            value(
                Self::NoError,
                bits::complete::tag(Self::NoError as u16, 4usize),
            ),
            value(
                Self::Format,
                bits::complete::tag(Self::Format as u16, 4usize),
            ),
            value(
                Self::Server,
                bits::complete::tag(Self::Server as u16, 4usize),
            ),
            value(Self::Name, bits::complete::tag(Self::Name as u16, 4usize)),
            value(
                Self::NotImplemented,
                bits::complete::tag(Self::Name as u16, 4usize),
            ),
            value(
                Self::Refused,
                bits::complete::tag(Self::Refused as u16, 4usize),
            ),
            value(Self::Reserved6, bits::complete::tag(Self::Reserved6 as u8, 4usize)),
            value(Self::Reserved7, bits::complete::tag(Self::Reserved7 as u8, 4usize)),
            value(Self::Reserved8, bits::complete::tag(Self::Reserved8 as u8, 4usize)),
            value(Self::Reserved9, bits::complete::tag(Self::Reserved9 as u8, 4usize)),
            value(Self::Reserved10, bits::complete::tag(Self::Reserved10 as u8, 4usize)),
            value(Self::Reserved11, bits::complete::tag(Self::Reserved11 as u8, 4usize)),
            value(Self::Reserved12, bits::complete::tag(Self::Reserved12 as u8, 4usize)),
            value(Self::Reserved13, bits::complete::tag(Self::Reserved13 as u8, 4usize)),
            value(Self::Reserved14, bits::complete::tag(Self::Reserved14 as u8, 4usize)),
            value(Self::Reserved15, bits::complete::tag(Self::Reserved15 as u8, 4usize)),
        ))(input)
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
                bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                    bits::complete::bool,
                    Opcode::parser,
                    bits::complete::bool,
                    bits::complete::bool,
                    bits::complete::bool,
                    bits::complete::bool,
                    bits::complete::take::<&[u8], u8, usize, nom::error::Error<(&[u8], usize)>>(
                        3usize,
                    ),
                    Rcode::parser,
                ))),
                be_u16,
                be_u16,
                be_u16,
                be_u16,
            )),
            |(id, (qr, opcode, aa, tc, rd, ra, _, rcode), qdcount, ancount, nscount, arcount)| {
                Self {
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
                }
            },
        )(buf)
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
enum Type {
    A = 1,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
}

impl Type {
    fn parser(input: &[u8]) -> IResult<&[u8], Self> {
        map_res(be_u16, |d: u16| match d {
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            3 => Ok(Self::MD),
            0u16 | 4u16..=u16::MAX => Err("unexpected TYPE value")
        })(input)
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u16)]
enum Qtype {
    A = 1,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AXFR = 252,
    MAILB,
    MAILA,
    ASTERISK,
}

impl Qtype {
    fn parser(input: &[u8]) -> IResult<&[u8], Self> {
        map_res(be_u16, |d: u16| match d {
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            3 => Ok(Self::MD),
            0u16 | 4u16..=u16::MAX => Err("unexpected QTYPE value")
        })(input)
    }
}

#[derive(Clone, Copy, Debug)]
enum Class {
    IN = 1,
    CS,
    CH,
    HS,
}

impl Class {
    fn parser(input: &[u8]) -> IResult<&[u8], Self> {
        map_res(be_u16, |d: u16| match d {
            1 => Ok(Self::IN),
            2 => Ok(Self::CS),
            3 => Ok(Self::CH),
            4 => Ok(Self::HS),
            0u16 | 5u16..=u16::MAX => Err("unexpected CLASS value")
        })(input)
    }
}

#[derive(Copy, Clone, Debug)]
enum Qclass {
    IN = 1,
    CS,
    CH,
    HS,
    ASTERISK = 255,
}

impl Qclass {
    fn parser(input: &[u8]) -> IResult<&[u8], Self> {
        map_res(be_u16, |d: u16| match d {
            1 => Ok(Self::IN),
            2 => Ok(Self::CS),
            3 => Ok(Self::CH),
            4 => Ok(Self::HS),
            255 => Ok(Self::ASTERISK),
            0u16 | 5u16..=254u16 | 256u16..=u16::MAX => Err("unexpected QCLASS value"),
        })(input)
    }
}

#[derive(Debug)]
struct DnsQuestion {
    qname: Vec<Vec<u8>>,
    qtype: Qtype,
    qclass: Qclass,
}

fn labels_parser(input: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
    many_till(label_parser, verify(label_parser, |v: &Vec<u8>| v.len() == 0))(input).map(|(i, (o, _))| (i, o))
}

fn label_parser(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    into(length_data(u8::<&[u8], nom::error::Error<&[u8]>>))(input)
}

fn serialize_labels(labels: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(64);
    for label in labels.iter() {
        assert!(label.len() < 64, "label.len() is longer ({}) than allowed (63)", label.len());
        buf.put_u8(label.len().try_into().expect("label.len() can't fit in u8"));
        buf.put_slice(label.as_slice());
    }
    buf.put_u8(0u8); // terminate NAME section with a label of length 0 (the "null label of the root")
    buf.into()
}

impl DnsQuestion {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(512);
        buf.put_slice(&serialize_labels(&self.qname));

        buf.put_u16(self.qtype as u16);
        buf.put_u16(self.qclass as u16);

        buf.to_vec()
    }

    fn parser(input: &[u8]) -> IResult<&[u8], Self> {
        tuple((
            labels_parser,
            Qtype::parser,
            Qclass::parser,
            ))(input).map(|(i, (qname, qtype, qclass))| (i, DnsQuestion {
            qname,
            qtype,
            qclass
        }))
    }
}

struct DnsResourceRecord {
    name: Vec<Vec<u8>>,
    rrtype: Type,
    class: Class,
    ttl: u32,
    rdata: Vec<u8>,
}

impl DnsResourceRecord {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(512);
        for label in self.name.iter() {
            assert!(label.len() < 64, "label.len() is longer ({}) than allowed (63)", label.len());
            buf.put_u8(label.len().try_into().expect("label.len() can't fit in u8"));
            buf.put_slice(label.as_slice());
        }
        buf.put_u8(0u8); // terminate NAME section with a label of length 0 (the "null label of the root")

        buf.put_u16(self.rrtype as u16);
        buf.put_u16(self.class as u16);
        buf.put_u32(self.ttl);

        buf.put_u16(self.rdata.len().try_into().expect("rdata.len() can't fit in u16"));
        buf.put_slice(self.rdata.as_slice());

        buf.to_vec()
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
                println!(
                    "Received {} bytes from {}\n{:?}",
                    size,
                    source,
                    &buf[..size]
                );
                let mut response = BytesMut::with_capacity(64);

                let (rest, req_head) = DnsHeader::parser(&buf)
                    .finish()
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
                    qdcount: req_head.qdcount,
                    ancount: req_head.qdcount,
                    nscount: 0,
                    arcount: 0,
                };
                println!("res_head: {:?}", res_head);
                response.put_slice(&res_head.serialize());

                for _ in 0..req_head.qdcount {
                    let (_rest, req_ques) = DnsQuestion::parser(rest)
                        .finish()
                        .expect("failed parsing request question");
                    println!("req_ques: {:?}", req_ques);

                    let res_ques = DnsQuestion {
                        qname: req_ques.qname,
                        qtype: Qtype::A,
                        qclass: Qclass::IN,
                    };
                    println!("res_ques: {:?}", res_ques);
                    response.put_slice(&res_ques.serialize());

                    // Answer
                    response.put_slice(&serialize_labels(&res_ques.qname));

                    response.put_u16(1u16); // TYPE for A record
                    response.put_u16(1u16); // CLASS for IN
                    response.put_u32(60u32); // TTL
                    response.put_u16(4u16); // RDLENGTH
                    response.put_slice(&[8u8, 8u8, 8u8, 8u8]); // RDATA corresponding to 8.8.8.8
                }

                let sentsz = udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
                println!("sent {} bytes back", sentsz);
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
