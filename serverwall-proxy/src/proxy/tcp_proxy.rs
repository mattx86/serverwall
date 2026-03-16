use tokio::io::{AsyncRead, AsyncWrite};

/// Transparent TCP proxy that forwards bytes bidirectionally between
/// a client stream and a backend stream.
pub struct TcpProxy;

impl TcpProxy {
    /// Proxy data bidirectionally between `client` and `backend`.
    ///
    /// Uses `tokio::io::copy_bidirectional` for efficient zero-copy I/O
    /// when the OS supports it.
    ///
    /// Returns `(bytes_from_client, bytes_from_backend)` on success, i.e.:
    ///   - `bytes_from_client`: bytes sent from the client to the backend
    ///   - `bytes_from_backend`: bytes sent from the backend to the client
    ///
    /// The proxy terminates gracefully when either side closes or an I/O
    /// error occurs.
    pub async fn proxy<C, B>(
        mut client: C,
        mut backend: B,
    ) -> std::io::Result<(u64, u64)>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let (client_to_backend, backend_to_client) =
            tokio::io::copy_bidirectional(&mut client, &mut backend).await?;
        Ok((client_to_backend, backend_to_client))
    }
}
