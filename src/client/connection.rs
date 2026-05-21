use futures::TryStreamExt;
use tokio_stream::wrappers::ReceiverStream;

use std::sync::atomic::{AtomicU16, Ordering};
use std::{future::Future, sync::Arc, vec};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{
        mpsc::{
            channel,
            error::{TryRecvError, TrySendError},
            Receiver, Sender,
        },
        oneshot, Mutex,
    },
};
use tokio_util::compat::*;
use tracing::*;

use crate::{codec, PixelFormat, Rect, VncEncoding, VncError, VncEvent, X11Event};
const CHANNEL_SIZE: usize = 4096;

#[cfg(not(target_arch = "wasm32"))]
use tokio::spawn;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::spawn_local as spawn;

use super::messages::{ClientMsg, ServerMsg};

struct ImageRect {
    rect: Rect,
    encoding: VncEncoding,
}

impl From<[u8; 12]> for ImageRect {
    fn from(buf: [u8; 12]) -> Self {
        Self {
            rect: Rect {
                x: ((buf[0] as u16) << 8) | buf[1] as u16,
                y: ((buf[2] as u16) << 8) | buf[3] as u16,
                width: ((buf[4] as u16) << 8) | buf[5] as u16,
                height: ((buf[6] as u16) << 8) | buf[7] as u16,
            },
            encoding: (((buf[8] as u32) << 24)
                | ((buf[9] as u32) << 16)
                | ((buf[10] as u32) << 8)
                | (buf[11] as u32))
                .into(),
        }
    }
}

impl ImageRect {
    async fn read<S>(reader: &mut S) -> Result<Self, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut rect_buf = [0_u8; 12];
        reader.read_exact(&mut rect_buf).await?;
        Ok(rect_buf.into())
    }
}

struct VncInner {
    name: String,
    // Reactive framebuffer dimensions. The server can resize the
    // framebuffer at any time via the DesktopSize pseudo-encoding
    // (RFB 6.7 §-223). Storing the dimensions in shared atomics lets
    // the decoder task update them when a SetDesktopSize rect arrives
    // and the input task observe the new values when forming the
    // FramebufferUpdateRequest for FullRefresh / Refresh — otherwise
    // FullRefresh would forever ask for the original handshake size
    // and the newly exposed area of an upscaled framebuffer would
    // never be requested or painted.
    screen: Arc<(AtomicU16, AtomicU16)>,
    input_ch: Sender<ClientMsg>,
    decoding_stop: Option<oneshot::Sender<()>>,
    net_conn_stop: Option<oneshot::Sender<()>>,
    closed: bool,
}

/// The instance of a connected vnc client
///
impl VncInner {
    async fn new<S>(
        mut stream: S,
        shared: bool,
        mut pixel_format: Option<PixelFormat>,
        encodings: Vec<VncEncoding>,
    ) -> Result<(Self, Receiver<VncEvent>), VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (conn_ch_tx, conn_ch_rx) = channel(CHANNEL_SIZE);
        let (input_ch_tx, input_ch_rx) = channel(CHANNEL_SIZE);
        let (output_ch_tx, output_ch_rx) = channel(CHANNEL_SIZE);
        let (decoding_stop_tx, decoding_stop_rx) = oneshot::channel();
        let (net_conn_stop_tx, net_conn_stop_rx) = oneshot::channel();

        trace!("client init msg");
        send_client_init(&mut stream, shared).await?;

        trace!("server init msg");
        let (name, (width, height)) =
            read_server_init(&mut stream, &mut pixel_format, &|e| async {
                output_ch_tx.send(e).await?;
                Ok(())
            })
            .await?;

        trace!("client encodings: {:?}", encodings);
        send_client_encoding(&mut stream, encodings).await?;

        trace!("Require the first frame");
        input_ch_tx
            .send(ClientMsg::FramebufferUpdateRequest(
                Rect {
                    x: 0,
                    y: 0,
                    width,
                    height,
                },
                0,
            ))
            .await?;

        // Shared, reactive framebuffer dimensions — see the comment on
        // `VncInner::screen`. Initialised to the server's handshake
        // size; the decoder task updates these atomics whenever a
        // DesktopSize pseudo-encoding rect arrives.
        //
        // Relaxed ordering throughout: the only invariant we need is
        // that the input task observes *some* value of the screen
        // dims when forming a FramebufferUpdateRequest, and that it
        // eventually observes the latest write after the decoder
        // updates them. There is no other shared state whose
        // happens-before relationship depends on the screen-dim
        // store (the decoder's `output_func(SetResolution)` channel
        // send carries its own synchronisation for downstream
        // consumers; the input task is purely a reader of the
        // atomic). Promoting to AcqRel/SeqCst would buy nothing and
        // cost a memory barrier per request on the hot path.
        let screen = Arc::new((AtomicU16::new(width), AtomicU16::new(height)));
        let decoder_screen = screen.clone();
        // Decoder also needs a back-channel into the input pipeline so
        // it can self-request a non-incremental full refresh the
        // instant DesktopSize updates the dims — otherwise the server
        // keeps shipping incremental updates for the old (smaller)
        // rect and the newly exposed area never paints. We hand it
        // its own input_ch_tx clone (cheap; tokio mpsc Sender is an
        // Arc internally).
        let decoder_input_tx = input_ch_tx.clone();

        // start the decoding thread
        spawn(async move {
            trace!("Decoding thread starts");
            let mut conn_ch_rx = {
                let conn_ch_rx = ReceiverStream::new(conn_ch_rx).into_async_read();
                FuturesAsyncReadCompatExt::compat(conn_ch_rx)
            };

            let output_func = |e| async {
                output_ch_tx.send(e).await?;
                Ok(())
            };

            let pf = pixel_format.as_ref().unwrap();
            if let Err(e) = asycn_vnc_read_loop(
                &mut conn_ch_rx,
                pf,
                &output_func,
                decoding_stop_rx,
                decoder_screen,
                decoder_input_tx,
            )
            .await
            {
                if let VncError::IoError(e) = e {
                    if let std::io::ErrorKind::UnexpectedEof = e.kind() {
                        // this should be a normal case when the network connection disconnects
                        // and we just send an EOF over the inner bridge between the process thread and the decode thread
                        // do nothing here
                    } else {
                        error!("Error occurs during the decoding {:?}", e);
                        let _ = output_func(VncEvent::Error(e.to_string())).await;
                    }
                } else {
                    error!("Error occurs during the decoding {:?}", e);
                    let _ = output_func(VncEvent::Error(e.to_string())).await;
                }
            }
            trace!("Decoding thread stops");
        });

        // start the traffic process thread
        spawn(async move {
            trace!("Net Connection thread starts");
            let _ =
                async_connection_process_loop(stream, input_ch_rx, conn_ch_tx, net_conn_stop_rx)
                    .await;
            trace!("Net Connection thread stops");
        });

        info!("VNC Client {name} starts");
        Ok((
            Self {
                name,
                screen,
                input_ch: input_ch_tx,
                decoding_stop: Some(decoding_stop_tx),
                net_conn_stop: Some(net_conn_stop_tx),
                closed: false,
            },
            output_ch_rx,
        ))
    }

    async fn input(&mut self, event: X11Event) -> Result<(), VncError> {
        if self.closed {
            Err(VncError::ClientNotRunning)
        } else {
            // Re-read the dimensions on every request — they may have
            // been updated by the decoder task in response to a
            // DesktopSize pseudo-encoding rect since the last call.
            let cur_w = self.screen.0.load(Ordering::Relaxed);
            let cur_h = self.screen.1.load(Ordering::Relaxed);
            let msg = match event {
                X11Event::Refresh => ClientMsg::FramebufferUpdateRequest(
                    Rect {
                        x: 0,
                        y: 0,
                        width: cur_w,
                        height: cur_h,
                    },
                    1,
                ),
                X11Event::FullRefresh => ClientMsg::FramebufferUpdateRequest(
                    Rect {
                        x: 0,
                        y: 0,
                        width: cur_w,
                        height: cur_h,
                    },
                    0, // non-incremental: server sends entire framebuffer
                ),
                X11Event::KeyEvent(key) => ClientMsg::KeyEvent(key.keycode, key.down),
                X11Event::PointerEvent(mouse) => {
                    ClientMsg::PointerEvent(mouse.position_x, mouse.position_y, mouse.bottons)
                }
                X11Event::CopyText(text) => ClientMsg::ClientCutText(text),
            };
            self.input_ch.send(msg).await?;
            Ok(())
        }
    }

    /// Stop the VNC engine and release resources
    ///
    fn close(&mut self) -> Result<(), VncError> {
        if self.net_conn_stop.is_some() {
            let net_conn_stop: oneshot::Sender<()> = self.net_conn_stop.take().unwrap();
            let _ = net_conn_stop.send(());
        }
        if self.decoding_stop.is_some() {
            let decoding_stop = self.decoding_stop.take().unwrap();
            let _ = decoding_stop.send(());
        }
        self.closed = true;
        Ok(())
    }
}

impl Drop for VncInner {
    fn drop(&mut self) {
        info!("VNC Client {} stops", self.name);
        let _ = self.close();
    }
}

pub struct VncClient {
    inner: Arc<Mutex<VncInner>>,
    /// Output channel behind its own dedicated mutex so that `recv_event()`
    /// can await new events without holding the inner lock.  This lets
    /// `input()` (which needs the inner lock) proceed freely while the
    /// consumer is blocked waiting for the server to send data.
    output_rx: Arc<Mutex<Receiver<VncEvent>>>,
}

impl VncClient {
    pub(super) async fn new<S>(
        stream: S,
        shared: bool,
        pixel_format: Option<PixelFormat>,
        encodings: Vec<VncEncoding>,
    ) -> Result<Self, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (inner, output_ch_rx) = VncInner::new(stream, shared, pixel_format, encodings).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            output_rx: Arc::new(Mutex::new(output_ch_rx)),
        })
    }

    /// Input a `X11Event` from the frontend
    ///
    pub async fn input(&self, event: X11Event) -> Result<(), VncError> {
        self.inner.lock().await.input(event).await
    }

    /// Receive the next `VncEvent` from the server, suspending the caller
    /// until one is available.
    ///
    /// Unlike the old `recv_event` implementation this does **not** hold the
    /// inner lock while waiting, so `input()` remains fully available even
    /// when the server is idle.
    pub async fn recv_event(&self) -> Result<VncEvent, VncError> {
        let mut rx = self.output_rx.lock().await;
        rx.recv().await.ok_or(VncError::ClientNotRunning)
    }

    /// Non-blocking poll: returns the next queued `VncEvent` if one is
    /// immediately available, or `Ok(None)` if the queue is empty.
    pub async fn poll_event(&self) -> Result<Option<VncEvent>, VncError> {
        let mut rx = self.output_rx.lock().await;
        match rx.try_recv() {
            Ok(e) => Ok(Some(e)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(VncError::ClientNotRunning),
        }
    }

    /// Stop the VNC engine and release resources
    ///
    pub async fn close(&self) -> Result<(), VncError> {
        self.inner.lock().await.close()
    }
}

impl Clone for VncClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            output_rx: self.output_rx.clone(),
        }
    }
}

async fn send_client_init<S>(stream: &mut S, shared: bool) -> Result<(), VncError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    trace!("Send shared flag: {}", shared);
    stream.write_u8(shared as u8).await?;
    Ok(())
}

async fn read_server_init<S, F, Fut>(
    stream: &mut S,
    pf: &mut Option<PixelFormat>,
    output_func: &F,
) -> Result<(String, (u16, u16)), VncError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(VncEvent) -> Fut,
    Fut: Future<Output = Result<(), VncError>>,
{
    // +--------------+--------------+------------------------------+
    // | No. of bytes | Type [Value] | Description                  |
    // +--------------+--------------+------------------------------+
    // | 2            | U16          | framebuffer-width in pixels  |
    // | 2            | U16          | framebuffer-height in pixels |
    // | 16           | PIXEL_FORMAT | server-pixel-format          |
    // | 4            | U32          | name-length                  |
    // | name-length  | U8 array     | name-string                  |
    // +--------------+--------------+------------------------------+

    let screen_width = stream.read_u16().await?;
    let screen_height = stream.read_u16().await?;
    let mut send_our_pf = false;

    output_func(VncEvent::SetResolution(
        (screen_width, screen_height).into(),
    ))
    .await?;

    let pixel_format = PixelFormat::read(stream).await?;
    if pf.is_none() {
        output_func(VncEvent::SetPixelFormat(pixel_format)).await?;
        let _ = pf.insert(pixel_format);
    } else {
        send_our_pf = true;
    }

    let name_len = stream.read_u32().await?;
    let mut name_buf = vec![0_u8; name_len as usize];
    stream.read_exact(&mut name_buf).await?;
    let name = String::from_utf8_lossy(&name_buf).into_owned();

    if send_our_pf {
        trace!("Send customized pixel format {:#?}", pf);
        ClientMsg::SetPixelFormat(*pf.as_ref().unwrap())
            .write(stream)
            .await?;
    }
    Ok((name, (screen_width, screen_height)))
}

async fn send_client_encoding<S>(
    stream: &mut S,
    encodings: Vec<VncEncoding>,
) -> Result<(), VncError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ClientMsg::SetEncodings(encodings).write(stream).await?;
    Ok(())
}

async fn asycn_vnc_read_loop<S, F, Fut>(
    stream: &mut S,
    pf: &PixelFormat,
    output_func: &F,
    mut stop_ch: oneshot::Receiver<()>,
    screen: Arc<(AtomicU16, AtomicU16)>,
    input_ch: Sender<ClientMsg>,
) -> Result<(), VncError>
where
    S: AsyncRead + Unpin,
    F: Fn(VncEvent) -> Fut,
    Fut: Future<Output = Result<(), VncError>>,
{
    let mut raw_decoder = codec::RawDecoder::new();
    let mut zrle_decoder = codec::ZrleDecoder::new();
    let mut tight_decoder = codec::TightDecoder::new();
    let mut trle_decoder = codec::TrleDecoder::new();
    let mut cursor = codec::CursorDecoder::new();

    // main decoding loop
    while let Err(oneshot::error::TryRecvError::Empty) = stop_ch.try_recv() {
        let server_msg = ServerMsg::read(stream).await?;
        trace!("Server message got: {:?}", server_msg);
        match server_msg {
            ServerMsg::FramebufferUpdate(rect_num) => {
                for _ in 0..rect_num {
                    let rect = ImageRect::read(stream).await?;
                    // trace!("Encoding: {:?}", rect.encoding);

                    match rect.encoding {
                        VncEncoding::Raw => {
                            raw_decoder
                                .decode(pf, &rect.rect, stream, output_func)
                                .await?;
                        }
                        VncEncoding::CopyRect => {
                            let source_x = stream.read_u16().await?;
                            let source_y = stream.read_u16().await?;
                            let mut src_rect = rect.rect;
                            src_rect.x = source_x;
                            src_rect.y = source_y;
                            output_func(VncEvent::Copy(rect.rect, src_rect)).await?;
                        }
                        VncEncoding::Tight => {
                            tight_decoder
                                .decode(pf, &rect.rect, stream, output_func)
                                .await?;
                        }
                        VncEncoding::Trle => {
                            trle_decoder
                                .decode(pf, &rect.rect, stream, output_func)
                                .await?;
                        }
                        VncEncoding::Zrle => {
                            zrle_decoder
                                .decode(pf, &rect.rect, stream, output_func)
                                .await?;
                        }
                        VncEncoding::CursorPseudo => {
                            cursor.decode(pf, &rect.rect, stream, output_func).await?;
                        }
                        VncEncoding::DesktopSizePseudo => {
                            // Update the shared dimensions BEFORE emitting
                            // the event so any FullRefresh the consumer
                            // dispatches in response uses the new size.
                            screen.0.store(rect.rect.width, Ordering::Relaxed);
                            screen.1.store(rect.rect.height, Ordering::Relaxed);
                            // Self-request a non-incremental full refresh
                            // for the new rect immediately. Without this,
                            // the server only ships incremental updates
                            // (heartbeat ticker + change-driven), and any
                            // newly exposed area of the framebuffer
                            // (everything outside the prior dimensions)
                            // never paints because nothing "changed"
                            // there from the server's point of view. We
                            // do this in-decoder rather than waiting for
                            // the consumer to round-trip a FullRefresh
                            // through its UI layer — that round-trip is
                            // long enough for the operator to perceive
                            // the screen as broken / "left-aligned"
                            // (only the originally-painted top-left
                            // chunk visible) before the request lands.
                            let req = ClientMsg::FramebufferUpdateRequest(
                                Rect {
                                    x: 0,
                                    y: 0,
                                    width: rect.rect.width,
                                    height: rect.rect.height,
                                },
                                0, // non-incremental
                            );
                            // try_send so the decoder never blocks on a
                            // saturated input channel — that would stall
                            // further reads from the network and we'd
                            // miss the very updates we're trying to
                            // prompt. We log both failure modes so a
                            // stuck input task is visible in support
                            // bundles:
                            //   - Full: input task is behind; the
                            //     periodic heartbeat ticker (every
                            //     ~16ms in the consumer wrapper) will
                            //     drain it shortly, and its next
                            //     request uses the now-current screen
                            //     dims so the missed full-refresh is
                            //     effectively replayed within one
                            //     tick.
                            //   - Closed: the consumer task has gone
                            //     away; we're shutting down anyway.
                            match input_ch.try_send(req) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => {
                                    warn!(
                                        "DesktopSize: input channel full, \
                                         post-resize full refresh deferred to next heartbeat"
                                    );
                                }
                                Err(TrySendError::Closed(_)) => {
                                    // Consumer gone — nothing else to
                                    // do; the decoder loop will exit
                                    // naturally on the next iteration.
                                }
                            }
                            output_func(VncEvent::SetResolution(
                                (rect.rect.width, rect.rect.height).into(),
                            ))
                            .await?;
                        }
                        VncEncoding::LastRectPseudo => {
                            break;
                        }
                    }
                }
            }
            // SetColorMapEntries,
            ServerMsg::Bell => {
                output_func(VncEvent::Bell).await?;
            }
            ServerMsg::ServerCutText(text) => {
                output_func(VncEvent::Text(text)).await?;
            }
        }
    }
    Ok(())
}

async fn async_connection_process_loop<S>(
    mut stream: S,
    mut input_ch: Receiver<ClientMsg>,
    conn_ch: Sender<std::io::Result<Vec<u8>>>,
    mut stop_ch: oneshot::Receiver<()>,
) -> Result<(), VncError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = [0; 65535];
    let mut pending = 0;

    // main traffic loop
    loop {
        if pending > 0 {
            match conn_ch.try_send(Ok(buffer[0..pending].to_owned())) {
                Err(TrySendError::Full(_message)) => (),
                Err(TrySendError::Closed(_message)) => break,
                Ok(()) => pending = 0,
            }
        }

        tokio::select! {
            _ = &mut stop_ch => break,
            result = stream.read(&mut buffer), if pending == 0 => {
                match result {
                    Ok(nread) => {
                        if nread > 0 {
                            match conn_ch.try_send(Ok(buffer[0..nread].to_owned())) {
                                Err(TrySendError::Full(_message)) => pending = nread,
                                Err(TrySendError::Closed(_message)) => break,
                                Ok(()) => ()
                            }
                        } else {
                            // According to the tokio's Doc
                            // https://docs.rs/tokio/latest/tokio/io/trait.AsyncRead.html
                            // if nread == 0, then EOF is reached
                            trace!("Net Connection EOF detected");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("{}", e.to_string());
                        break;
                    }
                }
            }
            Some(msg) = input_ch.recv() => {
                msg.write(&mut stream).await?;
            }
        }
    }

    // notify the decoding thread
    let _ = conn_ch
        .send(Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
        .await;

    Ok(())
}
