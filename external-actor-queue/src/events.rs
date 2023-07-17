use gstd::prelude::*;

// Alice.
pub static EVENT_DESTINATION: [u8; 32] =
    hex_literal::hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");

#[derive(Debug, Encode, Decode)]
pub enum Event {
    NewPayload { index: u64, size: u32 },
    InvalidProof { index: u64 },
}

pub fn send(event: Event) {
    gstd::msg::send(EVENT_DESTINATION.into(), event, 0).expect("Failed to send event");
}
