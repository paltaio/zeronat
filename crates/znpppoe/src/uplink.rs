//! Where this process's PPPoE sessions get their L2 segment: a bridge port on
//! the zeronat server, or a switch port on a peer's segment provider. Both
//! carry whole Ethernet frames in each direction.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{mpsc, Notify};
use tokio::time::sleep;

use zeronat::client::{
    ActiveTarget, ClientSettings, PeerSlotSession, PeerSlotSpec, ServerTarget, Transport,
};
use zeronat::dgram::{DgramRx, DgramTx, Frame};
use zeronat::proto::PROVIDES_SEGMENT;

use crate::bridge::{self, AbortOnDrop, Bridge, BridgeHold, Target};

const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long a bridge port may stay silent before the driver bounces it and
/// reconnects.
pub const UDP_IDLE: Duration = Duration::from_secs(120);
/// A bridge port whose sessions have all been down this long since the link was
/// up has lost its segment (e.g. the server restarted): the attach happens once
/// per channel and cannot re-establish in place, so an in-place PPPoE redial
/// loops forever and only a fresh channel re-attaches.
pub const REBRIDGE_GRACE: Duration = Duration::from_secs(30);

/// How the driver opens its next L2 channel.
pub enum Uplink {
    /// Dial the zeronat server and take a bridge port on it.
    Server(Dialer),
    /// Take the next session a segment consumer slot pairs. The slot re-pairs
    /// on its own backoff, so a dead pair arrives here as the next session
    /// rather than as a dial.
    Peer {
        sessions: mpsc::Receiver<PeerSlotSession>,
        /// The client the slot runs under. Held here so a driver that ends
        /// drops the control session and the switch port it holds on the
        /// provider.
        _client: AbortOnDrop,
    },
}

impl Uplink {
    /// The next live channel, or `None` once no further one can come up.
    pub async fn connect(&mut self) -> Option<Link> {
        match self {
            Uplink::Server(dialer) => Some(dialer.connect().await),
            Uplink::Peer { sessions, .. } => {
                let session = sessions.recv().await?;
                eprintln!("znpppoe: attached to {}'s segment", session.peer_id);
                Some(Link::peer(session))
            }
        }
    }
}

/// The client id of the peer serving the segment, distinct from this process's
/// own client id.
pub struct PeerId<'a>(pub &'a str);

/// Pair with `peer`'s L2 segment and hand every session that comes up to the
/// driver. The client this starts runs no session body of its own: the control
/// session it dials is what the pairing goes through, and the consumer slot
/// under it asks again whenever a pair dies. The client derives its id from
/// `id_prefix`, the same id the bridge path labels its port with.
pub fn peer(
    server: &str,
    secret: &str,
    credential: &str,
    id_prefix: &str,
    peer: PeerId<'_>,
) -> Uplink {
    let target = ServerTarget {
        name: "znpppoe".into(),
        addr: server.to_string(),
        secret: secret.to_string(),
        credential: credential.to_string(),
        transport: Transport::Auto,
    };
    let (tx, rx) = mpsc::channel(1);
    let settings = ClientSettings {
        servers: vec![target.clone()],
        tcp: Vec::new(),
        udp: Vec::new(),
        tap: None,
        tun: None,
        pppoe: Vec::new(),
        autostart: None,
        id_prefix: Some(id_prefix.to_string()),
        control: None,
        config: None,
        peers: vec![PeerSlotSpec::Consumer {
            peer_id: peer.0.to_string(),
            want: PROVIDES_SEGMENT,
            // The sessions ride this process's userspace stack, so the slot
            // opens no device and its frames come out on the seam below.
            adapter: None,
        }],
        peer_sessions: Some(tx),
    };
    let client = AbortOnDrop(crate::spawn(async move {
        match zeronat::client::run_switchable(ActiveTarget::new(target), settings).await {
            Ok(()) => eprintln!("znpppoe: the peer client stopped"),
            Err(e) => eprintln!("znpppoe: the peer client stopped: {e}"),
        }
    }));
    Uplink::Peer {
        sessions: rx,
        _client: client,
    }
}

/// How to reach the zeronat server, so the driver can redial after a drop.
pub struct Dialer {
    target: Target,
    secret: String,
    credential: String,
    client_id: String,
    backoff: Duration,
}

impl Dialer {
    pub fn new(target: Target, secret: String, credential: String, client_id: String) -> Self {
        Dialer {
            target,
            secret,
            credential,
            client_id,
            backoff: BACKOFF_START,
        }
    }

    /// Resolve and dial until a bridge port comes up, backing off between
    /// attempts.
    async fn connect(&mut self) -> Link {
        loop {
            match self.attempt().await {
                Ok(bridge) => {
                    self.backoff = BACKOFF_START;
                    return Link::bridge(bridge, self.client_id.clone());
                }
                Err(e) => {
                    eprintln!("znpppoe: {e:#}; retry in {:?}", self.backoff);
                    sleep(self.backoff).await;
                    self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
                }
            }
        }
    }

    /// One resolve-and-dial attempt.
    async fn attempt(&self) -> Result<Bridge> {
        let addr = self.target.resolve().await?;
        bridge::connect(addr, &self.secret, &self.credential, &self.client_id)
            .await
            .map_err(|e| {
                // A cached DHT address that stopped answering is re-resolved on
                // the next attempt.
                self.target.invalidate();
                e.context("tunnel connect failed")
            })
    }
}

/// One live L2 channel: whole Ethernet frames in each direction.
///
/// A bridge port fires `cancel` when the transport under it gives up, and its
/// silence is watched because a wedged path surfaces no error: a UDP
/// black-hole or an expired NAT mapping just stops delivering. A peer session
/// has neither. It dies by closing its receive half, and its silence is a quiet
/// segment, since the pair under it reaps a peer that stopped answering at its
/// own keepalive deadline.
pub enum Link {
    Bridge {
        rx: LinkRx,
        tx: LinkTx,
        cancel: Arc<Notify>,
        /// The KCP session, conv registration and receive pump, held for as
        /// long as the channel carries frames.
        _hold: BridgeHold,
    },
    Peer {
        rx: LinkRx,
        tx: LinkTx,
    },
}

impl Link {
    fn bridge(bridge: Bridge, name: String) -> Self {
        Link::Bridge {
            rx: LinkRx::Bridge(bridge.rx),
            tx: LinkTx::Bridge {
                tx: bridge.tx,
                name,
            },
            cancel: bridge.cancel,
            _hold: bridge.hold,
        }
    }

    fn peer(session: PeerSlotSession) -> Self {
        Link::Peer {
            rx: LinkRx::Peer(session.inbound),
            tx: LinkTx::Peer(session.outbound),
        }
    }

    /// The send half on its own, for callers that only put frames on the
    /// channel.
    pub fn tx(&self) -> &LinkTx {
        match self {
            Link::Bridge { tx, .. } | Link::Peer { tx, .. } => tx,
        }
    }
}

/// What a channel delivered: an Ethernet frame, or a control frame that only
/// proves the channel is alive.
pub enum Inbound {
    Frame(Vec<u8>),
    Alive,
}

/// The receive half of a channel.
pub enum LinkRx {
    Bridge(DgramRx),
    Peer(mpsc::Receiver<Vec<u8>>),
}

impl LinkRx {
    /// The next thing the channel delivers, or `None` once it is gone.
    pub async fn recv(&mut self) -> Option<Inbound> {
        match self {
            LinkRx::Bridge(rx) => Some(match rx.recv().await? {
                Frame::Data(frame) => Inbound::Frame(frame),
                Frame::Keepalive | Frame::Name(_) => Inbound::Alive,
            }),
            LinkRx::Peer(rx) => Some(Inbound::Frame(rx.recv().await?)),
        }
    }
}

/// The send half of a channel.
pub enum LinkTx {
    /// A bridge port, which carries the label the server's fleet view names it
    /// by.
    Bridge {
        tx: DgramTx,
        name: String,
    },
    Peer(mpsc::Sender<Vec<u8>>),
}

impl LinkTx {
    /// Put one Ethernet frame on the channel. A full queue drops the frame; a
    /// dead channel is what the receive half reports.
    pub async fn send(&self, frame: &[u8]) {
        match self {
            LinkTx::Bridge { tx, .. } => {
                tx.send(frame).await.ok();
            }
            LinkTx::Peer(tx) => {
                tx.try_send(frame.to_vec()).ok();
            }
        }
    }

    /// Hold the channel open. A bridge port probes the tunnel and re-announces
    /// its label, so a dropped attach frame self-heals.
    pub async fn keepalive(&self) {
        if let LinkTx::Bridge { tx, name } = self {
            tx.send_name(name).await.ok();
            tx.probe().await.ok();
        }
    }
}
