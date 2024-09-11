use serde::Serialize;
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use warp::{http::StatusCode, reject, Rejection, Reply};
pub enum Error {
    WrongCredentials,
    JWT,
    JWTCreation,
    MissingAuthorizationHeader,
    InvalidAuthorizationHeader,
    Unauthorized,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    message: String,
    status: String,
}

impl Debug for Error {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl warp::reject::Reject for Error {}

pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(_) = err.find::<reject::MethodNotAllowed>() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method Not Allowed";
    } else if let Some(e) = err.find::<Error>() {
        match e {
            Error::WrongCredentials => {
                code = StatusCode::FORBIDDEN;
                message = "Wrong credentials";
            }
            Error::JWT => {
                code = StatusCode::UNAUTHORIZED;
                message = "JWT not valid";
            }
            Error::JWTCreation => {
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal Server Error";
            }
            Error::MissingAuthorizationHeader => {
                code = StatusCode::UNAUTHORIZED;
                message = "Missing auth header";
            }
            Error::InvalidAuthorizationHeader => {
                code = StatusCode::UNAUTHORIZED;
                message = "Invalid auth header";
            }
            Error::Unauthorized => {
                code = StatusCode::FORBIDDEN;
                message = "No permission";
            }
            _ => {
                eprintln!("unhandled rejection: {:?}", err);
                code = StatusCode::BAD_REQUEST;
                message = "Internal Server Error";
            }
        }
    } else if dbg!(err.find::<warp::reject::MethodNotAllowed>().is_some()) {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method Not Allowed";
    } else {
        eprintln!("unhandled error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    let json = warp::reply::json(&ErrorResponse {
        message: message.into(),
        status: code.to_string(),
    });

    Ok(warp::reply::with_status(json, code))
}
