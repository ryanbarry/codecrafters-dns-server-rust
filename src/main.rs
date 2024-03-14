use std::net::UdpSocket;

use bytes::{BufMut, BytesMut};
use nom::{
    bits,
    branch::alt,
    combinator::{map, map_res, value, verify},
    number::complete::{be_u16, u8},
    sequence::tuple,
    IResult, Finish, multi::many_till, bytes::complete::take,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
enum Opcode {
    Query = 0,
    Iquery,
    Status,
    Reserved03,
    Reserved04,
    Reserved05,
    Reserved06,
    Reserved07,
    Reserved08,
    Reserved09,
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
            value(Self::Reserved03, bits::complete::tag(Self::Reserved03 as u8, 4usize)),
            value(Self::Reserved04, bits::complete::tag(Self::Reserved04 as u8, 4usize)),
            value(Self::Reserved05, bits::complete::tag(Self::Reserved05 as u8, 4usize)),
            value(Self::Reserved06, bits::complete::tag(Self::Reserved06 as u8, 4usize)),
            value(Self::Reserved07, bits::complete::tag(Self::Reserved07 as u8, 4usize)),
            value(Self::Reserved08, bits::complete::tag(Self::Reserved08 as u8, 4usize)),
            value(Self::Reserved09, bits::complete::tag(Self::Reserved09 as u8, 4usize)),
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
#[repr(u8)]
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
                bits::complete::tag(Self::NoError as u8, 4usize),
            ),
            value(
                Self::Format,
                bits::complete::tag(Self::Format as u8, 4usize),
            ),
            value(
                Self::Server,
                bits::complete::tag(Self::Server as u8, 4usize),
            ),
            value(Self::Name, bits::complete::tag(Self::Name as u8, 4usize)),
            value(
                Self::NotImplemented,
                bits::complete::tag(Self::Name as u8, 4usize),
            ),
            value(
                Self::Refused,
                bits::complete::tag(Self::Refused as u8, 4usize),
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
enum Class {
    IN = 1,
    CS,
    CH,
    HS,
}

impl Class {
    #[allow(dead_code)]
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
    qname: ParsedLabel,
    qtype: Qtype,
    qclass: Qclass,
}

#[allow(dead_code)]
struct DnsAnswer{}

struct DnsAuthority{}

struct DnsAdditional{}

#[derive(PartialEq, Eq, Debug)]
struct ParsedLabel {
    pos: usize,
    label: Vec<LabelSequenceElement>,
}

#[allow(dead_code)]
struct NLabelSequenceElement {
    data:LabelSequenceElement,
    next: Option<Box<NLabelSequenceElement>>,
}

#[derive(PartialEq, Eq, Debug)]
enum LabelSequenceElement {
    Literal(Vec<u8>),
    Pointer(usize),
    Zero,
}

#[allow(dead_code)]
struct DnsMessageParser {
    ques: Vec<DnsQuestion>,
    ans: Vec<u8>,
    auth: Option<DnsAuthority>,
    addl: Option<DnsAdditional>,
}

impl DnsMessageParser {
    fn parse(header: &DnsHeader, head_sz: usize, input: &[u8]) -> Self {
        let mut new_msg = DnsMessageParser {
            ques: vec![],
            ans: vec![],
            auth: None,
            addl: None,
        };

        let mut q_buf = vec![];
        let mut a_buf = vec![];
        let mut curr_pos = head_sz;

        let mut buf = input;
        println!("responding to {} questions", header.qdcount);
        for _ in 0..header.qdcount {
            let (rest, req_ques) = Self::question_parser(curr_pos, buf).finish().expect("parsing question failed");
            curr_pos += buf.len() - rest.len();
            buf = rest;

            let res_ques = DnsQuestion {
                qname: req_ques.qname,
                qtype: Qtype::A,
                qclass: Qclass::IN,
            };
            println!("res_ques: {:?}", res_ques);

            // Answer
            let mut ans = vec![];
            ans.put_slice(&serialize_labels(&res_ques.qname.label));

            ans.put_u16(1u16); // TYPE for A record
            ans.put_u16(1u16); // CLASS for IN
            ans.put_u32(59u32); // TTL
            ans.put_u16(4u16); // RDLENGTH
            ans.put_slice(&[8u8, 8u8, 8u8, 8u8]); // RDATA corresponding to 8.8.8.8

            q_buf.push(res_ques);
            a_buf.append(&mut ans);
        }

        new_msg.ques = q_buf;
        new_msg.ans = a_buf;
        new_msg
    }

    fn question_parser(starting_pos: usize, input: &[u8]) -> IResult<&[u8], DnsQuestion> {
        tuple((
            Self::labels_parser,
            Qtype::parser,
            Qclass::parser,
        ))(input).map(move |(i, (qname, qtype, qclass))| (i, DnsQuestion {
            qname: ParsedLabel {
                pos: starting_pos,
                label: qname
            },
            qtype,
            qclass
        }))
    }

    fn labels_parser(input: &[u8]) -> IResult<&[u8], Vec<LabelSequenceElement>> {
        println!("enter labels_parser");
        many_till(Self::label_parser, verify(Self::label_parser, |v: &LabelSequenceElement| match v {
            LabelSequenceElement::Zero | LabelSequenceElement::Pointer(_) => true,
            LabelSequenceElement::Literal(_) => false,
        }))(input)
            .map(|(i, (mut o, o2))| {
                o.push(o2);
                (i, o)
            })
    }

    fn label_parser(input: &[u8]) -> IResult<&[u8], LabelSequenceElement> {
        println!("\tenter label_parser");
        u8(input).map(|(input, byte1)| {
            if byte1 & 0xc0 == 0xc0 {
                println!("\t\tgot pointer");
                let mut offset: u16 = (byte1 ^ 0xc0).into();
                offset = offset << 8;
                u8(input).map(|(input, byte2)| {
                    offset += byte2 as u16;
                    (input, LabelSequenceElement::Pointer(offset.into()))
                })
            } else if byte1 != 0u8 {
                println!("\t\ttaking {} bytes", byte1);
                take(byte1)(input).map(|(i, o)| (i, LabelSequenceElement::Literal(o.to_vec())))
            } else {
                println!("\t\tgot zero");
                Ok((input, LabelSequenceElement::Zero))
            }
        })?
    }
}

fn serialize_labels(labels: &Vec<LabelSequenceElement>) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(64);
    for element in labels.iter() {
        match element {
            LabelSequenceElement::Literal(p) => {
                assert!(p.len() < 64, "label.len() is longer ({}) than allowed (63)", p.len());
                buf.put_u8(p.len().try_into().expect("label.len() can't fit in u8"));
                buf.put_slice(p.as_slice());
            }
            LabelSequenceElement::Pointer(_) => unimplemented!(),
            LabelSequenceElement::Zero => {
                buf.put_u8(0u8);
            }
        }
    }
    //buf.put_u8(0u8); // terminate NAME section with a label of length 0 (the "null label of the root")
    buf.into()
}

impl DnsQuestion {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(512);
        buf.put_slice(&serialize_labels(&self.qname.label));

        buf.put_u16(self.qtype as u16);
        buf.put_u16(self.qclass as u16);

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

                let ques_beg = size-rest.len();
                let parser = DnsMessageParser::parse(&req_head, ques_beg, rest);
                response.put_slice(&parser.ques.iter().flat_map(|q| q.serialize()).collect::<Vec<u8>>());
                response.put_slice(&parser.ans);
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
