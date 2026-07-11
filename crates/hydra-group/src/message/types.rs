use crate::MemberId;

#[derive(Debug, PartialEq, Eq)]
pub struct GroupOutboundMessage {
    pub sender: MemberId,
    pub index: u64,
    pub envelope: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GroupReceivedMessage {
    pub sender: MemberId,
    pub index: u64,
    pub content: Vec<u8>,
}
