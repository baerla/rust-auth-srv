use auth::{with_auth, Role};
use error::Error::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use warp::{reject, reply, Filter, Rejection, Reply};

mod auth;
mod error;

type Result<T> = std::result::Result<T, error::Error>;
type WebResult<T> = std::result::Result<T, Rejection>;
type Users = Arc<HashMap<String, User>>;

#[derive(Clone)]
pub struct User {
    pub user_id: String,
    pub email: String,
    pub password: String,
    pub role: String,
}
#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());

    let login_route = warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler);

    let user_route = warp::path!("user")
        .and(with_auth(Role::User))
        .and_then(user_handler);
    let admin_route = warp::path!("admin")
        .and(with_auth(Role::Admin))
        .and_then(admin_handler);

    let routes = login_route
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection);

    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}

fn with_users(users: Users) -> impl Filter<Extract = (Users,), Error = Infallible> + Clone {
    warp::any().map(move || users.clone())
}

pub async fn login_handler(users: Users, body: LoginRequest) -> WebResult<impl Reply> {
    match users
        .iter()
        .find(|(_user_id, user)| user.email == body.email && user.password == body.password)
    {
        Some((user_id, user)) => {
            let token = auth::create_jwt(&user_id, &Role::from_str(&user.role))
                .map_err(|e| reject::custom(e))?;
            Ok(reply::json(&LoginResponse { token }))
        }
        None => Err(reject::custom(WrongCredentials)),
    }
}

pub async fn user_handler(user_id: String) -> WebResult<impl Reply> {
    Ok(format!("Hello User {}", user_id))
}
pub async fn admin_handler(user_id: String) -> WebResult<impl Reply> {
    Ok(format!("Hello Admin {}", user_id))
}

fn init_users() -> HashMap<String, User> {
    let mut users = HashMap::new();
    users.insert(
        "1".to_string(),
        User {
            user_id: "1".to_string(),
            email: "user@userland.com".to_string(),
            password: "password".to_string(),
            role: "User".to_string(),
        },
    );
    users.insert(
        "2".to_string(),
        User {
            user_id: "2".to_string(),
            email: "admin@adminaty.com".to_string(),
            password: "admin".to_string(),
            role: "Admin".to_string(),
        },
    );
    users
}
