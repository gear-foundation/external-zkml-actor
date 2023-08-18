use codec::{Decode, Encode};
use gstd::{prelude::*, ActorId};

pub(crate) static mut QUEUE: Option<Vec<Message>> = None;
static mut ROLLING_INDEX: u64 = 0;

pub struct Queue;

#[derive(Clone, Encode, Decode, TypeInfo)]
pub struct Message {
    pub index: u64,
    pub sender: ActorId,
    pub payload: Vec<u8>,
    pub value: u128,
}

pub struct NewMessage {
    pub sender: ActorId,
    pub payload: Vec<u8>,
    pub value: u128,
}

impl Queue {
    pub fn queue() -> &'static Vec<Message> {
        unsafe { QUEUE.as_ref().expect("initialized during init") }
    }

    fn queue_mut() -> &'static mut Vec<Message> {
        unsafe { QUEUE.as_mut().expect("initialized during init") }
    }

    pub fn push(new_message: NewMessage) -> u64 {
        let new_index = unsafe {
            let val = ROLLING_INDEX;
            ROLLING_INDEX += 1;
            val
        };

        let msg = Message {
            index: new_index,
            sender: new_message.sender,
            payload: new_message.payload,
            value: new_message.value,
        };

        Self::queue_mut().push(msg);

        new_index
    }
}
