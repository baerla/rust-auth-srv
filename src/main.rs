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
#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
}

fn get_login_route(
    users: Arc<HashMap<String, User>>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler)
}

#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());

    let login_route = get_login_route(users);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use warp::http::{Response, StatusCode};
    use warp::hyper::body::Bytes;
    use warp::test::request;

    #[tokio::test]
    async fn login_success() {
        let users = Arc::new(init_users());
        let api = get_login_route(users);

        let resp = get_valid_user_token(api.clone()).await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn get_valid_user_token(
        api: impl Filter<Extract = impl Reply, Error = Rejection> + Clone + 'static,
    ) -> Response<Bytes> {
        request()
            .method("POST")
            .path("/login")
            .json(&LoginRequest {
                email: "user@userland.com".to_string(),
                password: "password".to_string(),
            })
            .reply(&api)
            .await
    }

    async fn get_valid_admin_token(
        api: impl Filter<Extract = impl Reply, Error = Rejection> + Clone + 'static,
    ) -> Response<Bytes> {
        request()
            .method("POST")
            .path("/login")
            .json(&LoginRequest {
                email: "admin@adminaty.com".to_string(),
                password: "admin".to_string(),
            })
            .reply(&api)
            .await
    }

    #[tokio::test]
    async fn login_wrong_credentials() {
        let users = Arc::new(init_users());
        let api = get_login_route(users);

        let resp = request()
            .method("POST")
            .path("/login")
            .json(&LoginRequest {
                email: "user@userland.com".to_string(),
                password: "wrongpassword".to_string(),
            })
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn user_route_success() {
        let api = warp::path!("user")
            .and(with_auth(Role::User))
            .and_then(user_handler);

        let user_token_bytes = get_valid_user_token(api.clone()).await;
        let token_string = String::from_utf8(user_token_bytes.body().to_vec()).expect("Invalid utf8");

        let resp = request()
            .method("GET")
            .path("/user")
            .header("Authorization", format!("Bearer {}", token_string))
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_route_success() {
        let api = warp::path!("admin")
            .and(with_auth(Role::Admin))
            .and_then(admin_handler);

        let admin_token_bytes = get_valid_admin_token(api.clone()).await;
        let token_string = String::from_utf8(admin_token_bytes.body().to_vec()).expect("Invalid utf8");

        println!("token_string: {}", token_string);

        let resp = request()
            .method("GET")
            .path("/admin")
            .header("Authorization", format!("Bearer {}", token_string))
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn user_route_old_token() {
        let api = warp::path!("user")
            .and(with_auth(Role::User))
            .and_then(user_handler);

        let resp = request()
            .method("GET")
            .path("/user")
            .header("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIyIiwicm9sZSI6IkFkbWluIiwiZXhwIjoxNzI2MDU1NjAzfQ.kj3zCxe24qNMXRyqNchVfhXLhWY6ceQaAH2Y0owqYVnCCbV_24-1sE-PkOdd9PjdcXduUYS1rPXMxfhkLntRbQ")
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_route_old_token() {
        let api = warp::path!("admin")
            .and(with_auth(Role::Admin))
            .and_then(admin_handler);

        let resp = request()
            .method("GET")
            .path("/admin")
            .header("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIyIiwicm9sZSI6IkFkbWluIiwiZXhwIjoxNzI2MDU1NjAzfQ.kj3zCxe24qNMXRyqNchVfhXLhWY6ceQaAH2Y0owqYVnCCbV_24-1sE-PkOdd9PjdcXduUYS1rPXMxfhkLntRbQ")
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn user_route_unauthorized() {
        let api = warp::path!("user")
            .and(with_auth(Role::User))
            .and_then(user_handler);

        let resp = request()
            .method("GET")
            .path("/user")
            .header("Authorization", "Bearer invalidtoken")
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_route_unauthorized() {
        let api = warp::path!("admin")
            .and(with_auth(Role::Admin))
            .and_then(admin_handler);

        let resp = request()
            .method("GET")
            .path("/admin")
            .header("Authorization", "Bearer invalidtoken")
            .reply(&api)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
