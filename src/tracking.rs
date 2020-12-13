use std::collections::HashMap;
use crate::dns::{
    DnsQuery,
    DnsRequestId,
};

#[derive(Default)]
pub struct RequestTracker {
    // Note: this should use something smarter that doesn't infinitely grow
    pending_requests: HashMap<DnsRequestId, DnsQuery>,
}

impl RequestTracker {
    pub fn add_query(&mut self, id: DnsRequestId, query: DnsQuery) {
        self.pending_requests.insert(id, query);
    }

    pub fn match_answer(&mut self, id: &DnsRequestId) -> Option<DnsQuery> {
        self.pending_requests.remove(id)
    }
}
