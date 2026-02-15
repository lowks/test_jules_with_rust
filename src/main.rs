use rocket::{
    fairing::AdHoc,
    get, launch, post, routes,
    serde::{json::Json, Deserialize, Serialize},
    FromForm,
};
use rocket_dyn_templates::{context, Template};
use rocket_sync_db_pools::{database, rusqlite};

#[database("sqlite_db")]
pub struct Db(rusqlite::Connection);

#[derive(Serialize, Deserialize, Debug, FromForm, Clone, PartialEq)]
#[serde(crate = "rocket::serde")]
pub struct Task {
    pub id: Option<i64>,
    pub name: String,
    pub status: String, // "new" or "done"
    pub date: String,   // ISO date string from date picker
}

impl Task {
    pub async fn all(db: &Db) -> Vec<Task> {
        db.run(|conn| {
            let mut stmt = conn
                .prepare("SELECT id, name, status, date FROM tasks ORDER BY date DESC")
                .expect("failed to prepare");
            let task_iter = stmt
                .query_map([], |row| {
                    Ok(Task {
                        id: Some(row.get(0)?),
                        name: row.get(1)?,
                        status: row.get(2)?,
                        date: row.get(3)?,
                    })
                })
                .expect("failed to query map");

            task_iter
                .map(|r| r.expect("failed to get row"))
                .collect::<Vec<Task>>()
        })
        .await
    }

    pub async fn insert(db: &Db, task: Task) -> i64 {
        db.run(move |conn| {
            conn.execute(
                "INSERT INTO tasks (name, status, date) VALUES (?, ?, ?)",
                [task.name, task.status, task.date],
            )
            .expect("failed to insert");
            conn.last_insert_rowid()
        })
        .await
    }
}

#[get("/")]
async fn index(db: Db) -> Template {
    let tasks = Task::all(&db).await;
    Template::render(
        "index",
        context! {
            tasks: tasks,
        },
    )
}

#[get("/tasks")]
async fn get_tasks(db: Db) -> Json<Vec<Task>> {
    Json(Task::all(&db).await)
}

#[post("/task", data = "<task>")]
async fn create_task_form(db: Db, task: rocket::form::Form<Task>) -> rocket::response::Redirect {
    Task::insert(&db, task.into_inner()).await;
    rocket::response::Redirect::to("/")
}

#[post("/tasks", format = "json", data = "<task>")]
async fn create_task_json(db: Db, task: Json<Task>) -> Json<Task> {
    let mut task_obj = task.into_inner();
    let id = Task::insert(&db, task_obj.clone()).await;
    task_obj.id = Some(id);
    Json(task_obj)
}

#[launch]
pub fn rocket() -> _ {
    rocket::build()
        .attach(Db::fairing())
        .attach(Template::fairing())
        .attach(AdHoc::on_ignite("Run Migrations", |rocket| async {
            let db = Db::get_one(&rocket).await.expect("database connection");
            db.run(|conn| {
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        status TEXT NOT NULL,
                        date TEXT NOT NULL
                    )",
                    [],
                )
                .expect("failed to create table");
            })
            .await;
            rocket
        }))
        .mount(
            "/",
            routes![index, get_tasks, create_task_form, create_task_json],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;

    #[test]
    fn test_index_page() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains("Task Tracker"));
        assert!(body.contains("Add New Task"));
    }

    #[test]
    fn test_empty_tasks_list() {
        // Use an in-memory database for a fresh state if possible,
        // but rocket() uses Rocket.toml which points to a file.
        // For simplicity, we just check the current state.
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_create_and_get_tasks_json() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // 1. Create a new task via JSON
        let task_name = format!("Test JSON Task {}", uuid::Uuid::new_v4());
        let response = client
            .post("/tasks")
            .header(ContentType::JSON)
            .body(format!(
                r#"{{"name": "{}", "status": "new", "date": "2023-10-27"}}"#,
                task_name
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let task: Task = response.into_json().expect("valid JSON task");
        assert_eq!(task.name, task_name);

        // 2. Get tasks again and verify it contains our new task
        let response = client.get("/tasks").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        assert!(tasks.iter().any(|t| t.name == task_name));
    }

    #[test]
    fn test_create_task_form() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // 1. Create a new task via Form
        let task_name = format!("Test Form Task {}", uuid::Uuid::new_v4());
        let body = format!("name={}&status=done&date=2023-12-25", task_name);
        let response = client
            .post("/task")
            .header(ContentType::Form)
            .body(body)
            .dispatch();

        // Should redirect to /
        assert_eq!(response.status(), Status::SeeOther);

        // 2. Verify it appears in JSON list
        let response = client.get("/tasks").dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        assert!(tasks
            .iter()
            .any(|t| t.name == task_name && t.status == "done"));
    }
}
