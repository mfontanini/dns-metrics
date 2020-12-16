use std::cmp::Ordering;
use std::sync::{
    Arc,
    Mutex,
};
use std::time::{
    Duration,
    SystemTime,
};
use std::collections::{
    BTreeMap,
    HashMap,
};
use crate::dns::{
    DnsQuery,
    DnsRequestId,
};

struct IdentifiedQuery {
    query: DnsQuery,
    id: u64,
}

struct ExpiringRequestIdentifier {
    request_id: DnsRequestId,
    expires_at: SystemTime,
}

// The inner contents of our tracker so we can hide them behind a lock
struct Inner {
    outstanding_requests: HashMap<DnsRequestId, IdentifiedQuery>,
    identifier_ttls: BTreeMap<u64, ExpiringRequestIdentifier>,
    current_id: u64,
    expiration: Duration,
}

// Note: the TTL logic here is pretty dumb: use a forever incrementing id to identify requests and put them
// in a tree map along with their expiration. When we want to expire old entries, we just need to iterate
// the tree in order until we hit the first element that's not expired yet.
//
// Ideally this would use something like a map -> doubly linked list iterator but I don't want to deal with that
#[derive(Clone)]
pub struct RequestTracker {
    inner: Arc<Mutex<Inner>>,
}

impl RequestTracker {
    pub fn with_expiration(expiration: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner{
                outstanding_requests: HashMap::new(),
                identifier_ttls: BTreeMap::new(),
                current_id: 0,
                expiration,
            })),
        }
    }

    pub fn add_query(&self, id: DnsRequestId, query: DnsQuery) {
        let mut inner = self.inner.lock().unwrap();
        let current_id = inner.current_id;
        let expireable_identifier = ExpiringRequestIdentifier {
            expires_at: query.timestamp.checked_add(inner.expiration).unwrap(),
            request_id: id.clone(),
        };
        let wrapper = IdentifiedQuery {
            query,
            id: current_id,
        };
        inner.identifier_ttls.insert(current_id, expireable_identifier);
        inner.current_id += 1;
        inner.outstanding_requests.insert(id, wrapper);
    }

    pub fn match_answer(&self, id: &DnsRequestId) -> Option<DnsQuery> {
        let mut inner = self.inner.lock().unwrap();
        match inner.outstanding_requests.remove(id) {
            Some(identified_query) => {
                inner.identifier_ttls.remove(&identified_query.id);
                Some(identified_query.query)
            },
            None => None,
        }
    }

    pub fn expire_requests(&self) -> usize {
        let now = SystemTime::now();
        let mut removed_entries = 0;
        let mut inner = self.inner.lock().unwrap();
        while !inner.identifier_ttls.is_empty() {
            let head = inner.identifier_ttls.iter().next().unwrap();
            if now.cmp(&head.1.expires_at) == Ordering::Less {
                break;
            }
            let id = *head.0;
            // Note: this can be simplified once https://github.com/rust-lang/rust/issues/62924 is stabilized
            drop(head);
            let request_id = inner.identifier_ttls.remove(&id).unwrap().request_id;
            inner.outstanding_requests.remove(&request_id);
            inner.identifier_ttls.remove(&id);
            removed_entries += 1
        }
        removed_entries
    }
}
