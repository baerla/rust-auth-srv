use crate::{error::Error, Result, WebResult};
use chrono::prelude::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
};

const BEARER: &str = "Bearer";
const JWT_SECRET: &[u8] = b"secret";

#[derive(Clone, PartialEq)]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn from_str(role: &str) -> Self {
        match role {
            "admin" => Role::Admin,
            "Admin" => Role::Admin,
            "user" => Role::User,
            "User" => Role::User,
            _ => Role::User,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Role::User => write!(f, "User"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub fn with_auth(role: Role) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (role.clone(), headers))
        .and_then(authorize)
    /* async move {
        let auth_header = match headers.get(AUTHORIZATION) {
            Some(header) => header,
            None => return Err(reject::custom(Error::MissingAuthorizationHeader)),
        };

        let auth_header_str = match auth_header.to_str() {
            Ok(header) => header,
            Err(_) => return Err(reject::custom(Error::InvalidAuthorizationHeader)),
        };

        let parts: Vec<&str> = auth_header_str.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(reject::custom(Error::InvalidAuthorizationHeader));
        }

        let token = parts[1];
        let claims = match decode::<Claims>(&token, &DecodingKey::from_secret(JWT_SECRET), &Validation::new(Algorithm::HS512)) {
            Ok(claims) => claims,
            Err(_) => return Err(reject::custom(Error::InvalidToken)),
        };

        if claims.exp < Utc::now().timestamp() as usize {
            return Err(reject::custom(Error::ExpiredToken));
        }

        if Role::from_str(&claims.role) != *role {
            return Err(reject::custom(Error::Unauthorized));
        }

        Ok(claims.sub)
    })*/
}

pub fn create_jwt(user_id: &str, role: &Role) -> Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .expect("valid timestamp")
        .timestamp();
    let claims = Claims {
        sub: user_id.to_owned(),
        role: role.to_string(),
        exp: expiration as usize,
    };

    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| Error::JWTCreation)
}

async fn authorize((role, headers): (Role, HeaderMap<HeaderValue>)) -> WebResult<String> {
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let decoded = decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::new(Algorithm::HS512),
            )
            .map_err(|_| reject::custom(Error::JWT))?;

            if role == Role::Admin && Role::from_str(&decoded.claims.role) != Role::Admin {
                return Err(reject::custom(Error::Unauthorized));
            }
            Ok(decoded.claims.sub)
        }
        Err(_) => Err(reject::custom(Error::InvalidAuthorizationHeader)),
    }
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String> {
    let header = match headers.get(AUTHORIZATION) {
        Some(header) => header,
        None => return Err(Error::MissingAuthorizationHeader),
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(header) => header,
        Err(_) => return Err(Error::MissingAuthorizationHeader),
    };
    if !auth_header.starts_with(BEARER) {
        return Err(Error::InvalidAuthorizationHeader);
    }
    Ok(auth_header.trim_start_matches(BEARER).trim().to_owned())
}
