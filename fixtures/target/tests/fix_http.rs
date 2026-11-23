use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &str,
    body: &str,
) -> (u16, String, String) {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        head.to_owned(),
        body.to_owned(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fix_modes_are_secret_only_and_exercise_each_flaw_over_http() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, scourge_fixture::app("secret".into()))
            .await
            .unwrap()
    });
    tokio::task::spawn_blocking(move || {
        let login = |name: &str| {
            let (_, head, _) = request(
                addr,
                "POST",
                "/app/login",
                "",
                &format!(r#"{{"username":"{name}","password":"{name}-password"}}"#),
            );
            head.lines()
                .find_map(|line| line.strip_prefix("set-cookie: "))
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        };
        let alice = format!("Cookie: {}\r\n", login("alice"));
        let bob = format!("Cookie: {}\r\n", login("bob"));
        let admin = format!("Cookie: {}\r\n", login("admin"));
        let secret = "X-Fixture-Admin-Secret: secret\r\n";
        let fix = |issue: &str, mode: &str, headers: &str| {
            request(
                addr,
                "POST",
                &format!("/app/_fix/{issue}"),
                headers,
                &json!({"mode": mode}).to_string(),
            )
            .0
        };
        for issue in [
            "cross_user_order_read",
            "cross_user_order_patch",
            "anonymous_private_read",
            "shared_private_cache",
        ] {
            assert_eq!(fix(issue, "real", &alice), 403);
            assert_eq!(fix(issue, "real", &admin), 403);
            assert_eq!(fix(issue, "real", "X-Fixture-Admin-Secret: wrong\r\n"), 403);
            assert_eq!(
                fix(
                    issue,
                    "real",
                    "X-Fixture-Admin-Secret: secret\r\nX-Fixture-Admin-Secret: secret\r\n"
                ),
                403
            );
        }
        for (issue, collection, alternate, method, attacker) in [
            (
                "cross_user_order_read",
                "orders",
                "order-lookup",
                "GET",
                bob.as_str(),
            ),
            (
                "cross_user_order_patch",
                "orders",
                "order-lookup",
                "PATCH",
                bob.as_str(),
            ),
            (
                "anonymous_private_read",
                "private-reports",
                "private-report-lookup",
                "GET",
                "",
            ),
            (
                "shared_private_cache",
                "cached-reports",
                "cached-report-lookup",
                "GET",
                "",
            ),
        ] {
            let (_, _, created) = request(
                addr,
                "POST",
                &format!("/app/api/{collection}"),
                &alice,
                r#"{"note":"canary-one","detail":"canary-two"}"#,
            );
            let id = serde_json::from_str::<Value>(&created).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let path = format!("/app/api/{collection}/{id}");
            let alt = format!("/app/api/{alternate}/{id}");
            let payload = if method == "PATCH" {
                r#"{"note":"canary-one","detail":"canary-two"}"#
            } else {
                ""
            };
            let prime = || {
                assert_eq!(request(addr, "GET", &path, &alice, "").0, 200);
            };
            prime();
            assert!(matches!(
                request(addr, method, &path, attacker, payload).0,
                200 | 204
            ));
            assert_eq!(fix(issue, "real", secret), 204);
            prime();
            assert!(matches!(
                request(addr, method, &path, attacker, payload).0,
                401 | 404
            ));
            assert!(matches!(
                request(addr, method, &alt, attacker, payload).0,
                401 | 404
            ));
            if method == "PATCH" {
                for (route, value) in [(&path, "owner-primary"), (&alt, "owner-alternate")] {
                    let update = json!({"note": value, "detail": "canary-two"}).to_string();
                    assert_eq!(request(addr, "PATCH", route, &alice, &update).0, 204);
                    let (status, _, body) = request(addr, "GET", &path, &alice, "");
                    assert_eq!(status, 200);
                    assert_eq!(
                        serde_json::from_str::<Value>(&body).unwrap(),
                        json!({"note": value, "detail": "canary-two"})
                    );
                }
                assert_eq!(request(addr, "PATCH", &path, &alice, payload).0, 204);
            } else {
                for route in [&path, &alt] {
                    let (status, _, body) = request(addr, "GET", route, &alice, "");
                    assert_eq!(status, 200);
                    assert_eq!(
                        serde_json::from_str::<Value>(&body).unwrap(),
                        json!({"note": "canary-one", "detail": "canary-two"})
                    );
                }
            }
            assert_eq!(fix(issue, "partial_route", secret), 204);
            prime();
            assert!(matches!(
                request(addr, method, &path, attacker, payload).0,
                401 | 404
            ));
            assert!(matches!(
                request(addr, method, &alt, attacker, payload).0,
                200 | 204
            ));
            if method == "GET" {
                assert_eq!(fix(issue, "partial_field", secret), 204);
                prime();
                let (_, _, body) = request(addr, method, &path, attacker, payload);
                assert!(!body.contains("canary-one"));
                assert!(body.contains("canary-two"));
            }
            assert_eq!(fix(issue, "removed_route", secret), 204);
            assert_eq!(request(addr, method, &path, &alice, payload).0, 404);
            assert_eq!(fix(issue, "broken_login", secret), 204);
            assert_eq!(request(addr, "GET", "/app/api/me", &alice, "").0, 401);
            assert_eq!(
                request(
                    addr,
                    "POST",
                    "/app/login",
                    "",
                    r#"{"username":"bob","password":"bob-password"}"#
                )
                .0,
                401
            );
            assert_eq!(fix(issue, "vulnerable", secret), 204);
        }
    })
    .await
    .unwrap();
    server.abort();
}
