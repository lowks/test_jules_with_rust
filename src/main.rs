use rocket::{
    fairing::AdHoc,
    fairing::{Fairing, Info, Kind},
    form::FromFormField,
    fs::{relative, FileServer},
    get,
    http::{Cookie, Header, SameSite, Status},
    launch, post,
    request::{FromRequest, Outcome},
    response::Redirect,
    routes,
    serde::{json::Json, Deserialize, Serialize},
    FromForm, Request, Response,
};
use rocket_dyn_templates::{context, Template};
use rocket_sync_db_pools::{database, rusqlite};

#[database("sqlite_db")]
pub struct Db(rusqlite::Connection);

const CSRF_COOKIE_NAME: &str = "csrf_token";

pub struct CsrfToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CsrfToken {
    type Error = std::convert::Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = request.cookies();
        if let Some(cookie) = cookies.get(CSRF_COOKIE_NAME) {
            Outcome::Success(CsrfToken(cookie.value().to_string()))
        } else {
            let token = uuid::Uuid::new_v4().to_string();
            cookies.add(
                Cookie::build((CSRF_COOKIE_NAME, token.clone()))
                    .path("/")
                    .same_site(SameSite::Lax)
                    .http_only(true)
                    .build(),
            );
            Outcome::Success(CsrfToken(token))
        }
    }
}

#[derive(FromForm)]
pub struct CsrfForm {
    pub csrf_token: String,
}

pub struct XCsrfToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for XCsrfToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("X-CSRF-Token") {
            Some(token) => Outcome::Success(XCsrfToken(token.to_string())),
            None => Outcome::Error((Status::Forbidden, ())),
        }
    }
}

#[derive(FromForm)]
pub struct TaskForm {
    #[field(validate = len(1..255))]
    pub name: String,
    pub status: TaskStatus,
    pub date: String,
    pub csrf_token: String,
}

#[derive(Debug, FromFormField, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(crate = "rocket::serde", rename_all = "lowercase")]
pub enum TaskStatus {
    #[field(value = "new")]
    New,
    #[field(value = "done")]
    Done,
}

#[derive(Debug, FromFormField, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(crate = "rocket::serde", rename_all = "lowercase")]
pub enum SortColumn {
    Name,
    Status,
    Date,
}

#[derive(Debug, FromFormField, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(crate = "rocket::serde", rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::New => write!(f, "new"),
            TaskStatus::Done => write!(f, "done"),
        }
    }
}

impl rusqlite::types::ToSql for TaskStatus {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.to_string().into())
    }
}

impl rusqlite::types::FromSql for TaskStatus {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        value.as_str().map(|s| match s {
            "done" => TaskStatus::Done,
            _ => TaskStatus::New,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, FromForm, Clone, PartialEq)]
#[serde(crate = "rocket::serde")]
pub struct Task {
    pub id: Option<i64>,
    #[field(validate = len(1..255))]
    pub name: String,
    pub status: TaskStatus,
    pub date: String, // ISO date string from date picker
}

impl Task {
    pub async fn all(
        db: &Db,
        sort_by: SortColumn,
        order: SortDirection,
    ) -> Result<Vec<Task>, rusqlite::Error> {
        db.run(move |conn| {
            let sql_column = match sort_by {
                SortColumn::Name => "name",
                SortColumn::Status => "status",
                SortColumn::Date => "date",
            };
            let sql_order = match order {
                SortDirection::Asc => "ASC",
                SortDirection::Desc => "DESC",
            };
            let query = format!(
                "SELECT id, name, status, date FROM tasks ORDER BY {} {}",
                sql_column, sql_order
            );
            let mut stmt = conn.prepare(&query)?;
            let task_iter = stmt.query_map([], |row| {
                Ok(Task {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    status: row.get(2)?,
                    date: row.get(3)?,
                })
            })?;

            task_iter.collect::<Result<Vec<Task>, rusqlite::Error>>()
        })
        .await
    }

    pub async fn insert(db: &Db, task: Task) -> Result<i64, rusqlite::Error> {
        db.run(move |conn| {
            conn.execute(
                "INSERT INTO tasks (name, status, date) VALUES (?, ?, ?)",
                rusqlite::params![task.name, task.status, task.date],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    pub async fn find(db: &Db, id: i64) -> Option<Task> {
        db.run(move |conn| {
            conn.query_row(
                "SELECT id, name, status, date FROM tasks WHERE id = ?",
                [id],
                |row| {
                    Ok(Task {
                        id: Some(row.get(0)?),
                        name: row.get(1)?,
                        status: row.get(2)?,
                        date: row.get(3)?,
                    })
                },
            )
            .ok()
        })
        .await
    }

    pub async fn update(db: &Db, id: i64, task: Task) -> Result<bool, rusqlite::Error> {
        db.run(move |conn| {
            Ok(conn.execute(
                "UPDATE tasks SET name = ?, status = ?, date = ? WHERE id = ?",
                rusqlite::params![task.name, task.status, task.date, id],
            )? > 0)
        })
        .await
    }

    pub async fn delete(db: &Db, id: i64) -> Result<bool, rusqlite::Error> {
        db.run(move |conn| {
            Ok(conn.execute("DELETE FROM tasks WHERE id = ?", rusqlite::params![id])? > 0)
        })
        .await
    }
}

#[get("/?<sort_by>&<order>")]
async fn index(
    db: Db,
    sort_by: Option<SortColumn>,
    order: Option<SortDirection>,
    csrf_token: CsrfToken,
) -> Result<Template, Status> {
    let sort_by = sort_by.unwrap_or(SortColumn::Date);
    let order = order.unwrap_or(SortDirection::Desc);

    let tasks = Task::all(&db, sort_by, order)
        .await
        .map_err(|_| Status::InternalServerError)?;

    let next_order_name = if sort_by == SortColumn::Name && order == SortDirection::Asc {
        SortDirection::Desc
    } else {
        SortDirection::Asc
    };

    let next_order_status = if sort_by == SortColumn::Status && order == SortDirection::Asc {
        SortDirection::Desc
    } else {
        SortDirection::Asc
    };

    let next_order_date = if sort_by == SortColumn::Date && order == SortDirection::Asc {
        SortDirection::Desc
    } else {
        SortDirection::Asc
    };

    Ok(Template::render(
        "index",
        context! {
            tasks: tasks,
            sort_by: sort_by,
            order: order,
            next_order_name: next_order_name,
            next_order_status: next_order_status,
            next_order_date: next_order_date,
            csrf_token: csrf_token.0,
        },
    ))
}

#[get("/tasks?<sort_by>&<order>")]
async fn get_tasks(
    db: Db,
    sort_by: Option<SortColumn>,
    order: Option<SortDirection>,
) -> Result<Json<Vec<Task>>, Status> {
    let sort_by = sort_by.unwrap_or(SortColumn::Date);
    let order = order.unwrap_or(SortDirection::Desc);
    let tasks = Task::all(&db, sort_by, order)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Json(tasks))
}

#[post("/task", data = "<task>")]
async fn create_task_form(
    db: Db,
    csrf_token: CsrfToken,
    task: rocket::form::Form<TaskForm>,
) -> Result<Redirect, Status> {
    if csrf_token.0 != task.csrf_token {
        return Err(Status::Forbidden);
    }
    let task_obj = Task {
        id: None,
        name: task.name.clone(),
        status: task.status,
        date: task.date.clone(),
    };
    Task::insert(&db, task_obj)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/"))
}

#[post("/tasks", format = "json", data = "<task>")]
async fn create_task_json(
    db: Db,
    csrf_token: CsrfToken,
    x_csrf_token: XCsrfToken,
    task: Json<Task>,
) -> Result<Json<Task>, Status> {
    if x_csrf_token.0 != csrf_token.0 {
        return Err(Status::Forbidden);
    }

    let mut task_obj = task.into_inner();
    if task_obj.name.is_empty() || task_obj.name.len() > 255 {
        return Err(Status::UnprocessableEntity);
    }
    let id = Task::insert(&db, task_obj.clone())
        .await
        .map_err(|_| Status::InternalServerError)?;
    task_obj.id = Some(id);
    Ok(Json(task_obj))
}

#[get("/task/<id>")]
async fn view_task(db: Db, id: i64, csrf_token: CsrfToken) -> Option<Template> {
    Task::find(&db, id).await.map(|task| {
        Template::render(
            "view",
            context! {
                task: task,
                csrf_token: csrf_token.0,
            },
        )
    })
}

#[get("/task/<id>/edit")]
async fn edit_task(db: Db, id: i64, csrf_token: CsrfToken) -> Option<Template> {
    Task::find(&db, id).await.map(|task| {
        Template::render(
            "edit",
            context! {
                task: task,
                csrf_token: csrf_token.0,
            },
        )
    })
}

#[post("/task/<id>", data = "<task>")]
async fn update_task(
    db: Db,
    id: i64,
    csrf_token: CsrfToken,
    task: rocket::form::Form<TaskForm>,
) -> Result<Redirect, Status> {
    if csrf_token.0 != task.csrf_token {
        return Err(Status::Forbidden);
    }
    let task_obj = Task {
        id: Some(id),
        name: task.name.clone(),
        status: task.status,
        date: task.date.clone(),
    };
    Task::update(&db, id, task_obj)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/"))
}

#[post("/task/<id>/delete", data = "<form>")]
async fn delete_task(
    db: Db,
    id: i64,
    csrf_token: CsrfToken,
    form: rocket::form::Form<CsrfForm>,
) -> Result<Redirect, Status> {
    if csrf_token.0 != form.csrf_token {
        return Err(Status::Forbidden);
    }
    Task::delete(&db, id)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/"))
}

pub struct SecurityHeaders;

#[rocket::async_trait]
impl Fairing for SecurityHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Security Headers",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self'; font-src https://cdnjs.cloudflare.com;"));
        response.set_header(Header::new(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        ));
        response.set_header(Header::new("X-Frame-Options", "DENY"));
        response.set_header(Header::new("X-Content-Type-Options", "nosniff"));
        response.set_header(Header::new(
            "Referrer-Policy",
            "strict-origin-when-cross-origin",
        ));
        response.set_header(Header::new(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=()",
        ));
    }
}

#[launch]
pub fn rocket() -> _ {
    rocket::build()
        .attach(Db::fairing())
        .attach(SecurityHeaders)
        .attach(Template::fairing())
        .attach(AdHoc::on_ignite("Run Migrations", |rocket| async {
            let db = match Db::get_one(&rocket).await {
                Some(db) => db,
                None => return rocket,
            };
            let _ = db
                .run(|conn| {
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('new', 'done')),
                        date TEXT NOT NULL
                    )",
                        [],
                    )
                })
                .await;
            rocket
        }))
        .mount("/static", FileServer::from(relative!("static")))
        .mount(
            "/",
            routes![
                index,
                get_tasks,
                create_task_form,
                create_task_json,
                view_task,
                edit_task,
                update_task,
                delete_task
            ],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;

    fn get_csrf_token(client: &Client) -> String {
        client.get("/").dispatch();
        client
            .cookies()
            .get(CSRF_COOKIE_NAME)
            .unwrap()
            .value()
            .to_string()
    }

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
        let csrf_token = get_csrf_token(&client);

        // 1. Create a new task via JSON
        let task_name = format!("Test JSON Task {}", uuid::Uuid::new_v4());
        let response = client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token))
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
        let csrf_token = get_csrf_token(&client);

        // 1. Create a new task via Form
        let task_name = format!("Test Form Task {}", uuid::Uuid::new_v4());
        let body = format!(
            "name={}&status=done&date=2023-12-25&csrf_token={}",
            task_name, csrf_token
        );
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
            .any(|t| t.name == task_name && t.status == TaskStatus::Done));
    }

    #[test]
    fn test_view_task() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);

        // 1. Create a task
        let task_name = format!("View Test Task {}", uuid::Uuid::new_v4());
        let response = client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token))
            .body(format!(
                r#"{{"name": "{}", "status": "new", "date": "2023-10-27"}}"#,
                task_name
            ))
            .dispatch();
        let task: Task = response.into_json().expect("valid JSON task");
        let id = task.id.unwrap();

        // 2. View the task
        let response = client.get(format!("/task/{}", id)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains(&task_name));
        assert!(body.contains("Task Details"));
    }

    #[test]
    fn test_edit_and_update_task() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);

        // 1. Create a task
        let task_name = format!("Edit Test Task {}", uuid::Uuid::new_v4());
        let response = client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token.clone()))
            .body(format!(
                r#"{{"name": "{}", "status": "new", "date": "2023-10-27"}}"#,
                task_name
            ))
            .dispatch();
        let task: Task = response.into_json().expect("valid JSON task");
        let id = task.id.unwrap();

        // 2. Get edit page
        let response = client.get(format!("/task/{}/edit", id)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert!(response.into_string().unwrap().contains("Edit Task"));

        // 3. Update the task
        let updated_name = format!("Updated Task {}", uuid::Uuid::new_v4());
        let body = format!(
            "name={}&status=done&date=2024-01-01&csrf_token={}",
            updated_name, csrf_token
        );
        let response = client
            .post(format!("/task/{}", id))
            .header(ContentType::Form)
            .body(body)
            .dispatch();
        assert_eq!(response.status(), Status::SeeOther);

        // 4. Verify update
        let response = client.get(format!("/task/{}", id)).dispatch();
        let body = response.into_string().unwrap();
        assert!(body.contains(&updated_name));
        assert!(body.contains("Done"));
        assert!(body.contains("2024-01-01"));
    }

    #[test]
    fn test_delete_task() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);

        // 1. Create a task
        let task_name = format!("Delete Test Task {}", uuid::Uuid::new_v4());
        let response = client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token.clone()))
            .body(format!(
                r#"{{"name": "{}", "status": "new", "date": "2023-10-27"}}"#,
                task_name
            ))
            .dispatch();
        let task: Task = response.into_json().expect("valid JSON task");
        let id = task.id.unwrap();

        // 2. Delete the task
        let response = client
            .post(format!("/task/{}/delete", id))
            .header(ContentType::Form)
            .body(format!("csrf_token={}", csrf_token))
            .dispatch();
        assert_eq!(response.status(), Status::SeeOther);

        // 3. Verify it's gone
        let response = client.get(format!("/task/{}", id)).dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    #[test]
    fn test_task_not_found() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/task/999999").dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    #[test]
    fn test_security_headers() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);

        let headers = response.headers();
        assert!(headers.get_one("Content-Security-Policy").is_some());
        assert!(headers.get_one("Strict-Transport-Security").is_some());
        assert_eq!(headers.get_one("X-Frame-Options"), Some("DENY"));
        assert_eq!(headers.get_one("X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(
            headers.get_one("Referrer-Policy"),
            Some("strict-origin-when-cross-origin")
        );
    }

    #[test]
    fn test_input_validation_name_too_short() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);
        let body = format!("name=&status=new&date=2023-12-25&csrf_token={}", csrf_token);
        let response = client
            .post("/task")
            .header(ContentType::Form)
            .body(body)
            .dispatch();

        // Rocket returns 422 Unprocessable Entity when validation fails
        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    #[test]
    fn test_input_validation_name_too_long() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);
        let long_name = "a".repeat(256);
        let body = format!(
            "name={}&status=new&date=2023-12-25&csrf_token={}",
            long_name, csrf_token
        );
        let response = client
            .post("/task")
            .header(ContentType::Form)
            .body(body)
            .dispatch();

        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    #[test]
    fn test_input_validation_invalid_status() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);
        let body = format!(
            "name=Test&status=invalid&date=2023-12-25&csrf_token={}",
            csrf_token
        );
        let response = client
            .post("/task")
            .header(ContentType::Form)
            .body(body)
            .dispatch();

        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    #[test]
    fn test_input_validation_json_name_too_long() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);
        let long_name = "a".repeat(256);
        let response = client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token))
            .body(format!(
                r#"{{"name": "{}", "status": "new", "date": "2023-10-27"}}"#,
                long_name
            ))
            .dispatch();

        // If this passes (200 OK), then JSON validation is missing
        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    #[test]
    fn test_csrf_protection_enforcement() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // 1. Try to create a task via Form without CSRF token
        let response = client
            .post("/task")
            .header(ContentType::Form)
            .body("name=Test&status=new&date=2023-12-25")
            .dispatch();
        assert_eq!(response.status(), Status::UnprocessableEntity);

        // 1.5 Try to create a task via Form with WRONG CSRF token
        let response = client
            .post("/task")
            .header(ContentType::Form)
            .body("name=Test&status=new&date=2023-12-25&csrf_token=wrong")
            .dispatch();
        assert_eq!(response.status(), Status::Forbidden);

        // 2. Try to create a task via JSON without X-CSRF-Token header
        let response = client
            .post("/tasks")
            .header(ContentType::JSON)
            .body(r#"{"name": "Test", "status": "new", "date": "2023-10-27"}"#)
            .dispatch();
        assert_eq!(response.status(), Status::Forbidden);
    }

    #[test]
    fn test_sorting_by_name() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = get_csrf_token(&client);
        let uuid = uuid::Uuid::new_v4().to_string();
        let name_a = format!("A Task {}", uuid);
        let name_b = format!("B Task {}", uuid);

        client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token.clone()))
            .body(format!(
                r#"{{"name": "{}", "status": "new", "date": "2023-01-01"}}"#,
                name_a
            ))
            .dispatch();
        client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token.clone()))
            .body(format!(
                r#"{{"name": "{}", "status": "new", "date": "2023-01-01"}}"#,
                name_b
            ))
            .dispatch();

        // 1. Get sorted by name ASC
        let response = client.get("/tasks?sort_by=name&order=asc").dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");

        let filtered_tasks: Vec<&Task> = tasks
            .iter()
            .filter(|t| t.name == name_a || t.name == name_b)
            .collect();
        assert_eq!(filtered_tasks.len(), 2);
        assert_eq!(filtered_tasks[0].name, name_a);
        assert_eq!(filtered_tasks[1].name, name_b);

        // 2. Get sorted by name DESC
        let response = client.get("/tasks?sort_by=name&order=desc").dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        let filtered_tasks: Vec<&Task> = tasks
            .iter()
            .filter(|t| t.name == name_a || t.name == name_b)
            .collect();
        assert_eq!(filtered_tasks.len(), 2);
        assert_eq!(filtered_tasks[0].name, name_b);
        assert_eq!(filtered_tasks[1].name, name_a);
    }
}
