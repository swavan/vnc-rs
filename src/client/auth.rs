use super::security;
use crate::{VncError, VncVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SecurityType {
    Invalid,
    None,
    VncAuth,
    RA2,
    RA2ne,
    Tight,
    Ultra,
    Tls,
    VeNCrypt,
    GtkVncSasl,
    Md5Hash,
    ColinDeanXvp,
    AppleRemoteDesktop,
}

impl TryFrom<u8> for SecurityType {
    type Error = VncError;
    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(SecurityType::Invalid),
            1 => Ok(SecurityType::None),
            2 => Ok(SecurityType::VncAuth),
            5 => Ok(SecurityType::RA2),
            6 => Ok(SecurityType::RA2ne),
            16 => Ok(SecurityType::Tight),
            17 => Ok(SecurityType::Ultra),
            18 => Ok(SecurityType::Tls),
            19 => Ok(SecurityType::VeNCrypt),
            20 => Ok(SecurityType::GtkVncSasl),
            21 => Ok(SecurityType::Md5Hash),
            22 => Ok(SecurityType::ColinDeanXvp),
            30 => Ok(SecurityType::AppleRemoteDesktop),
            invalid => Err(VncError::InvalidSecurityTyep(invalid)),
        }
    }
}

impl From<SecurityType> for u8 {
    fn from(e: SecurityType) -> Self {
        match e {
            SecurityType::Invalid => 0,
            SecurityType::None => 1,
            SecurityType::VncAuth => 2,
            SecurityType::RA2 => 5,
            SecurityType::RA2ne => 6,
            SecurityType::Tight => 16,
            SecurityType::Ultra => 17,
            SecurityType::Tls => 18,
            SecurityType::VeNCrypt => 19,
            SecurityType::GtkVncSasl => 20,
            SecurityType::Md5Hash => 21,
            SecurityType::ColinDeanXvp => 22,
            SecurityType::AppleRemoteDesktop => 30,
        }
    }
}

impl SecurityType {
    pub(super) async fn read<S>(reader: &mut S, version: &VncVersion) -> Result<Vec<Self>, VncError>
    where
        S: AsyncRead + Unpin,
    {
        match version {
            VncVersion::RFB33 => {
                let security_type = reader.read_u32().await?;
                let security_type = (security_type as u8).try_into()?;
                if let SecurityType::Invalid = security_type {
                    let _ = reader.read_u32().await?;
                    let mut err_msg = String::new();
                    reader.read_to_string(&mut err_msg).await?;
                    return Err(VncError::General(err_msg));
                }
                Ok(vec![security_type])
            }
            _ => {
                let num = reader.read_u8().await?;

                if num == 0 {
                    let _ = reader.read_u32().await?;
                    let mut err_msg = String::new();
                    reader.read_to_string(&mut err_msg).await?;
                    return Err(VncError::General(err_msg));
                }
                let mut sec_types = vec![];
                for _ in 0..num {
                    let byte = reader.read_u8().await?;
                    match byte.try_into() {
                        Ok(st) => sec_types.push(st),
                        Err(_) => {
                            tracing::debug!("Skipping unknown security type: {}", byte);
                        }
                    }
                }
                tracing::trace!("Server supported security type: {:?}", sec_types);
                if sec_types.is_empty() {
                    return Err(VncError::General(
                        "No supported security type offered by server".to_string(),
                    ));
                }
                Ok(sec_types)
            }
        }
    }

    pub(super) async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        writer.write_all(&[(*self).into()]).await?;
        Ok(())
    }
}

#[allow(dead_code)]
pub(super) enum AuthResult {
    Ok,
    Failed,
}

impl From<u32> for AuthResult {
    fn from(num: u32) -> Self {
        match num {
            0 => AuthResult::Ok,
            _ => AuthResult::Failed,
        }
    }
}

impl From<AuthResult> for u32 {
    fn from(e: AuthResult) -> Self {
        match e {
            AuthResult::Ok => 0,
            AuthResult::Failed => 1,
        }
    }
}

pub(super) struct AuthHelper {
    challenge: [u8; 16],
    key: [u8; 8],
}

impl AuthHelper {
    pub(super) async fn read<S>(reader: &mut S, credential: &str) -> Result<Self, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut challenge = [0; 16];
        reader.read_exact(&mut challenge).await?;

        let credential_len = credential.len();
        let mut key = [0u8; 8];
        for (i, key_i) in key.iter_mut().enumerate() {
            let c = if i < credential_len {
                credential.as_bytes()[i]
            } else {
                0
            };
            let mut cs = 0u8;
            for j in 0..8 {
                cs |= ((c >> j) & 1) << (7 - j)
            }
            *key_i = cs;
        }

        Ok(Self { challenge, key })
    }

    pub(super) async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        let encrypted = security::des::encrypt(&self.challenge, &self.key);
        writer.write_all(&encrypted).await?;
        Ok(())
    }

    pub(super) async fn finish<S>(self, reader: &mut S) -> Result<AuthResult, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = reader.read_u32().await?;
        Ok(result.into())
    }
}
