#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStateType {
    Init,
    Responded,
    Established,
    Rotating,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeMessageType {
    Init,
    Resp,
    Final,
}
