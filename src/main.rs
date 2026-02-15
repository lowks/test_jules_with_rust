use rocket::{get, post, launch, routes, serde::{Serialize, Deserialize, json::Json}, fairing::AdHoc};
use rocket_sync_db_pools::{database, rusqlite};

#[database("sqlite_db")]
struct Db(rusqlite::Connection);

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "rocket::serde")]
struct Entry {
    id: Option<i64>,
    text: String,
}

#[get("/entries")]
async fn get_entries(db: Db) -> Json<Vec<Entry>> {
    let entries = db.run(|conn| {
        let mut stmt = conn.prepare("SELECT id, text FROM entries").expect("failed to prepare");
        let entry_iter = stmt.query_map([], |row| {
            Ok(Entry {
                id: Some(row.get(0)?),
                text: row.get(1)?,
            })
        }).expect("failed to query map");

        entry_iter.map(|r| r.expect("failed to get row")).collect::<Vec<Entry>>()
    }).await;

    Json(entries)
}

#[post("/entries", format = "json", data = "<entry>")]
async fn create_entry(db: Db, entry: Json<Entry>) -> Json<Entry> {
    let text = entry.text.clone();
    let id = db.run(move |conn| {
        conn.execute("INSERT INTO entries (text) VALUES (?)", [text]).expect("failed to insert");
        conn.last_insert_rowid()
    }).await;

    Json(Entry {
        id: Some(id),
        text: entry.text.clone(),
    })
}

#[launch]
pub fn rocket() -> _ {
    rocket::build()
        .attach(Db::fairing())
        .attach(AdHoc::on_ignite("Run Migrations", |rocket| async {
            let db = Db::get_one(&rocket).await.expect("database connection");
            db.run(|conn| {
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, text TEXT NOT NULL)",
                    [],
                ).expect("failed to create table");
            }).await;
            rocket
        }))
        .mount("/", routes![get_entries, create_entry])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::local::blocking::Client;
    use rocket::http::{Status, ContentType};

    #[test]
    fn test_create_and_get_entries() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // 1. Get initial entries
        let response = client.get("/entries").dispatch();
        assert_eq!(response.status(), Status::Ok);

        // 2. Create a new entry
        let response = client.post("/entries")
            .header(ContentType::JSON)
            .body(r#"{"text": "Test Entry"}"#)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let entry: Entry = response.into_json().expect("valid JSON entry");
        assert_eq!(entry.text, "Test Entry");
        assert!(entry.id.is_some());

        // 3. Get entries again and verify it contains our new entry
        let response = client.get("/entries").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let entries: Vec<Entry> = response.into_json().expect("valid JSON entries");
        assert!(entries.iter().any(|e| e.text == "Test Entry"));
    }
}
