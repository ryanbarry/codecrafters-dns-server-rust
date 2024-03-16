use std::{net::UdpSocket, collections::VecDeque, env};

use bytes::{BufMut, BytesMut};
use nom::{
    bits,
    branch::alt,
    bytes::complete::take,
    combinator::{map, map_res, value, verify},
    multi::many_till,
    number::complete::{be_u16, u8},
    sequence::tuple,
    Finish, IResult,
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
            value(
                Self::Reserved03,
                bits::complete::tag(Self::Reserved03 as u8, 4usize),
            ),
            value(
                Self::Reserved04,
                bits::complete::tag(Self::Reserved04 as u8, 4usize),
            ),
            value(
                Self::Reserved05,
                bits::complete::tag(Self::Reserved05 as u8, 4usize),
            ),
            value(
                Self::Reserved06,
                bits::complete::tag(Self::Reserved06 as u8, 4usize),
            ),
            value(
                Self::Reserved07,
                bits::complete::tag(Self::Reserved07 as u8, 4usize),
            ),
            value(
                Self::Reserved08,
                bits::complete::tag(Self::Reserved08 as u8, 4usize),
            ),
            value(
                Self::Reserved09,
                bits::complete::tag(Self::Reserved09 as u8, 4usize),
            ),
            value(
                Self::Reserved10,
                bits::complete::tag(Self::Reserved10 as u8, 4usize),
            ),
            value(
                Self::Reserved11,
                bits::complete::tag(Self::Reserved11 as u8, 4usize),
            ),
            value(
                Self::Reserved12,
                bits::complete::tag(Self::Reserved12 as u8, 4usize),
            ),
            value(
                Self::Reserved13,
                bits::complete::tag(Self::Reserved13 as u8, 4usize),
            ),
            value(
                Self::Reserved14,
                bits::complete::tag(Self::Reserved14 as u8, 4usize),
            ),
            value(
                Self::Reserved15,
                bits::complete::tag(Self::Reserved15 as u8, 4usize),
            ),
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
            value(
                Self::Reserved6,
                bits::complete::tag(Self::Reserved6 as u8, 4usize),
            ),
            value(
                Self::Reserved7,
                bits::complete::tag(Self::Reserved7 as u8, 4usize),
            ),
            value(
                Self::Reserved8,
                bits::complete::tag(Self::Reserved8 as u8, 4usize),
            ),
            value(
                Self::Reserved9,
                bits::complete::tag(Self::Reserved9 as u8, 4usize),
            ),
            value(
                Self::Reserved10,
                bits::complete::tag(Self::Reserved10 as u8, 4usize),
            ),
            value(
                Self::Reserved11,
                bits::complete::tag(Self::Reserved11 as u8, 4usize),
            ),
            value(
                Self::Reserved12,
                bits::complete::tag(Self::Reserved12 as u8, 4usize),
            ),
            value(
                Self::Reserved13,
                bits::complete::tag(Self::Reserved13 as u8, 4usize),
            ),
            value(
                Self::Reserved14,
                bits::complete::tag(Self::Reserved14 as u8, 4usize),
            ),
            value(
                Self::Reserved15,
                bits::complete::tag(Self::Reserved15 as u8, 4usize),
            ),
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
            0u16 | 4u16..=u16::MAX => Err("unexpected QTYPE value"),
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

#[derive(Debug, Clone)]
struct DnsQuestion {
    qname: ParsedLabel,
    qtype: Qtype,
    qclass: Qclass,
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

#[derive(PartialEq, Eq, Debug, Clone)]
struct ParsedLabel {
    pos: usize,
    label: Vec<LabelSequenceElement>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum LabelSequenceElement {
    Literal(Vec<u8>),
    Pointer(usize),
    Zero,
}

struct DnsMessageParser {
}

impl DnsMessageParser {
    fn parse(header: &DnsHeader, head_sz: usize, input: &[u8]) -> (Vec<DnsQuestion>, usize) {
        let mut q_buf = vec![];
        let mut curr_pos = head_sz;

        let mut buf = input;
        for _ in 0..header.qdcount {
            let (rest, req_ques) = Self::question_parser(curr_pos, q_buf.clone(), buf)
                .finish()
                .expect("parsing question failed");
            curr_pos += buf.len() - rest.len();
            buf = rest;

            let res_ques = DnsQuestion {
                qname: req_ques.qname,
                qtype: Qtype::A,
                qclass: Qclass::IN,
            };
            q_buf.push(res_ques);
        }
        (q_buf, curr_pos - head_sz)
    }

    fn question_parser(
        starting_pos: usize,
        mut q_buf: Vec<DnsQuestion>,
        input: &[u8],
    ) -> IResult<&[u8], DnsQuestion> {
        tuple((Self::labels_parser, Qtype::parser, Qclass::parser))(input).map(
            move |(i, (qname, qtype, qclass))| {
                (
                    i,
                    DnsQuestion {
                        qname: ParsedLabel {
                            pos: starting_pos,
                            label: qname
                                .iter()
                                .flat_map(|lse| match lse {
                                    LabelSequenceElement::Literal(_)
                                    | LabelSequenceElement::Zero => vec![lse.clone()],
                                    LabelSequenceElement::Pointer(ptr) => {
                                        q_buf
                                            .iter_mut()
                                            .filter_map(|prevq| {
                                                if prevq.qname.pos <= *ptr {
                                                    let mut cursor = prevq.qname.pos;
                                                    let mut s = VecDeque::from(prevq.qname.label.clone());
                                                    while cursor != (*ptr-1) && s.len() > 0 {
                                                        match s.pop_front().unwrap() {
                                                            LabelSequenceElement::Literal(v) => {
                                                                let element_len = v.len();
                                                                cursor += element_len;
                                                            }
                                                            LabelSequenceElement::Zero => {
                                                                cursor += 1;
                                                            },
                                                            _ => panic!("pointer resolved to pointer"),
                                                        }
                                                    }
                                                    Some(s.into())
                                                } else {
                                                    None
                                                }
                                            })
                                            .last().expect("a label")
                                    }
                                })
                                .collect::<Vec<LabelSequenceElement>>()
                        },
                        qtype,
                        qclass,
                    },
                )
            },
        )
    }

    fn labels_parser(input: &[u8]) -> IResult<&[u8], Vec<LabelSequenceElement>> {
        //println!("enter labels_parser");
        many_till(
            Self::label_parser,
            verify(Self::label_parser, |v: &LabelSequenceElement| match v {
                LabelSequenceElement::Zero | LabelSequenceElement::Pointer(_) => true,
                LabelSequenceElement::Literal(_) => false,
            }),
        )(input)
        .map(|(i, (mut o, o2))| {
            o.push(o2);
            (i, o)
        })
    }

    fn label_parser(input: &[u8]) -> IResult<&[u8], LabelSequenceElement> {
        //println!("\tenter label_parser");
        u8(input).map(|(input, byte1)| {
            if byte1 & 0xc0 == 0xc0 {
                //println!("\t\tgot pointer");
                let mut offset: u16 = (byte1 ^ 0xc0).into();
                offset = offset << 8;
                u8(input).map(|(input, byte2)| {
                    offset += byte2 as u16;
                    (input, LabelSequenceElement::Pointer(offset.into()))
                })
            } else if byte1 != 0u8 {
                //println!("\t\ttaking {} bytes", byte1);
                take(byte1)(input).map(|(i, o)| (i, LabelSequenceElement::Literal(o.to_vec())))
            } else {
                //println!("\t\tgot zero");
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
                assert!(
                    p.len() < 64,
                    "label.len() is longer ({}) than allowed (63)",
                    p.len()
                );
                buf.put_u8(p.len().try_into().expect("label.len() can't fit in u8"));
                buf.put_slice(p.as_slice());
            }
            LabelSequenceElement::Pointer(p) => {
                buf.put_u8(0xc0u8);
                buf.put_u8(*p as u8);
            }
            LabelSequenceElement::Zero => {
                buf.put_u8(0u8);
            }
        }
    }
    //buf.put_u8(0u8); // terminate NAME section with a label of length 0 (the "null label of the root")
    buf.into()
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    let argv: Vec<String> = env::args().collect();
    let resolver = if argv.len() == 3 && argv[1] == "--resolver" {
        let raddr = argv[2].clone();
        println!("got a resolver arg for {}", raddr);
        Some(raddr)
    } else {
        None
    };

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

                let (rest, req_head) = DnsHeader::parser(&buf[..size])
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

                let ques_beg = size - rest.len();
                let questions = DnsMessageParser::parse(&req_head, ques_beg, rest);
                for q in &questions.0 {
                    println!("res_ques: {:?}", q);
                }
                response.put_slice(
                    &questions.0
                        .iter()
                        .flat_map(|q| q.serialize())
                        .collect::<Vec<u8>>(),
                );
                match resolver {
                    Some(ref raddr) => {
                        let udp_socket = UdpSocket::bind("127.0.0.1:2054").expect("Failed to bind to resolver-listener address");
                        let mut ups_buf = [0; 512];
                        let mut down_res = BytesMut::with_capacity(512);

                        for question in &questions.0 {
                            let fhead = DnsHeader {
                                id: 1,
                                qr: false,
                                opcode: Opcode::Query,
                                aa: false,
                                tc: false,
                                rd: true,
                                ra: false,
                                rcode: Rcode::NoError,
                                qdcount: 1,
                                ancount: 0,
                                nscount: 0,
                                arcount: 0,
                            };
                            let mut freq = BytesMut::with_capacity(64);
                            freq.put_slice(&fhead.serialize());
                            freq.put_slice(&question.serialize());

                            let sentsz = udp_socket.send_to(&freq, raddr).expect("failed to forward query");
                            println!("sent {} bytes to upstream for query", sentsz);
                            match udp_socket.recv_from(&mut ups_buf) {
                                Ok((sz, _src)) => {
                                    println!("got {} bytes from upstream in response", sz);
                                    let (f_rest, fres_head) = DnsHeader::parser(&ups_buf[..sz])
                                        .finish()
                                        .expect("failed parsing forwarder response header");
                                    println!("fres_head: {:?}", fres_head);

                                    let fres_q_beg = size - rest.len();
                                    let (_, ans_offs) = DnsMessageParser::parse(&fres_head, fres_q_beg, f_rest);
                                    down_res.put_slice(&f_rest[ans_offs..]);
                                }
                                Err(e) => {
                                    eprintln!("Error receiving from upstream: {}", e);
                                    break;
                                }
                            }
                        }
                        response.put_slice(&down_res);
                    }
                    None => {
                        let mut ans = vec![];
                        for rq in &questions.0 {
                            ans.put_slice(&serialize_labels(&rq.qname.label));
                            ans.put_u16(1u16); // TYPE for A record
                            ans.put_u16(1u16); // CLASS for IN
                            ans.put_u32(59u32); // TTL
                            ans.put_u16(4u16); // RDLENGTH
                            ans.put_slice(&[8u8, 8u8, 8u8, 8u8]); // RDATA corresponding to 8.8.8.8
                        }

                        response.put_slice(&ans);
                    }
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
