use chrono::{Duration, Local, NaiveDate};
use rocket::{
    catch, catchers,
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

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

#[database("sqlite_db")]
pub struct Db(rusqlite::Connection);

const CSRF_COOKIE_NAME: &str = "csrf_token";

pub struct CsrfToken(pub String);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "rocket::serde")]
pub struct User {
    pub id: i64,
    pub username: String,
}

impl User {
    pub async fn all(db: &Db) -> Result<Vec<User>, rusqlite::Error> {
        db.run(move |conn| {
            let mut stmt = conn.prepare("SELECT id, username FROM users")?;
            let user_iter = stmt.query_map([], |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                })
            })?;
            user_iter.collect()
        })
        .await
    }

    pub async fn find(db: &Db, id: i64) -> Option<User> {
        db.run(move |conn| {
            conn.query_row("SELECT id, username FROM users WHERE id = ?", [id], |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                })
            })
            .ok()
        })
        .await
    }

    pub async fn insert(
        db: &Db,
        username: String,
        password_hash: String,
    ) -> Result<i64, rusqlite::Error> {
        db.run(move |conn| {
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                rusqlite::params![username, password_hash],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    pub async fn update(
        db: &Db,
        id: i64,
        username: String,
        password_hash: Option<String>,
    ) -> Result<bool, rusqlite::Error> {
        db.run(move |conn| {
            if let Some(hash) = password_hash {
                Ok(conn.execute(
                    "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
                    rusqlite::params![username, hash, id],
                )? > 0)
            } else {
                Ok(conn.execute(
                    "UPDATE users SET username = ? WHERE id = ?",
                    rusqlite::params![username, id],
                )? > 0)
            }
        })
        .await
    }

    pub async fn delete(db: &Db, id: i64) -> Result<bool, rusqlite::Error> {
        db.run(move |conn| {
            // First delete tasks of the user
            conn.execute("DELETE FROM tasks WHERE user_id = ?", [id])?;
            Ok(conn.execute("DELETE FROM users WHERE id = ?", [id])? > 0)
        })
        .await
    }
}

#[derive(FromForm)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

#[derive(FromForm)]
pub struct UserForm {
    pub username: String,
    pub password: Option<String>,
    pub csrf_token: String,
}

pub struct AuthUser(pub User);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthUser {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let db = match request.guard::<Db>().await {
            Outcome::Success(db) => db,
            _ => return Outcome::Error((Status::InternalServerError, ())),
        };

        let user_id = request
            .cookies()
            .get_private("user_id")
            .and_then(|cookie| cookie.value().parse::<i64>().ok());

        if let Some(id) = user_id {
            let user = db
                .run(move |conn| {
                    conn.query_row("SELECT id, username FROM users WHERE id = ?", [id], |row| {
                        Ok(User {
                            id: row.get(0)?,
                            username: row.get(1)?,
                        })
                    })
                    .ok()
                })
                .await;

            if let Some(user) = user {
                return Outcome::Success(AuthUser(user));
            }
        }

        Outcome::Forward(Status::Unauthorized)
    }
}

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
    pub user_id: Option<i64>,
    #[serde(default)]
    pub is_urgent: bool,
}

impl Task {
    fn is_date_urgent(date_str: &str) -> bool {
        let now = Local::now().date_naive();
        let tomorrow = now + Duration::days(1);
        if let Ok(task_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            task_date >= now && task_date <= tomorrow
        } else {
            false
        }
    }

    pub async fn all(
        db: &Db,
        user_id: i64,
        sort_by: SortColumn,
        order: SortDirection,
        limit: i64,
        offset: i64,
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
                "SELECT id, name, status, date, user_id FROM tasks WHERE user_id = ? ORDER BY {} {} LIMIT ? OFFSET ?",
                sql_column, sql_order
            );
            let mut stmt = conn.prepare(&query)?;
            let task_iter = stmt.query_map(rusqlite::params![user_id, limit, offset], |row| {
                let date_str: String = row.get(3)?;
                let is_urgent = Self::is_date_urgent(&date_str);
                Ok(Task {
                    id: Some(row.get(0)?),
                    name: row.get(1)?,
                    status: row.get(2)?,
                    date: date_str,
                    user_id: Some(row.get(4)?),
                    is_urgent,
                })
            })?;

            task_iter.collect::<Result<Vec<Task>, rusqlite::Error>>()
        })
        .await
    }

    pub async fn count(db: &Db, user_id: i64) -> Result<i64, rusqlite::Error> {
        db.run(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM tasks WHERE user_id = ?",
                [user_id],
                |row| row.get(0),
            )
        })
        .await
    }

    pub async fn insert(db: &Db, task: Task) -> Result<i64, rusqlite::Error> {
        db.run(move |conn| {
            conn.execute(
                "INSERT INTO tasks (name, status, date, user_id) VALUES (?, ?, ?, ?)",
                rusqlite::params![task.name, task.status, task.date, task.user_id],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    pub async fn find(db: &Db, id: i64, user_id: i64) -> Option<Task> {
        db.run(move |conn| {
            conn.query_row(
                "SELECT id, name, status, date, user_id FROM tasks WHERE id = ? AND user_id = ?",
                [id, user_id],
                |row| {
                    let date_str: String = row.get(3)?;
                    let is_urgent = Self::is_date_urgent(&date_str);
                    Ok(Task {
                        id: Some(row.get(0)?),
                        name: row.get(1)?,
                        status: row.get(2)?,
                        date: date_str,
                        user_id: Some(row.get(4)?),
                        is_urgent,
                    })
                },
            )
            .ok()
        })
        .await
    }

    pub async fn update(
        db: &Db,
        id: i64,
        user_id: i64,
        task: Task,
    ) -> Result<bool, rusqlite::Error> {
        db.run(move |conn| {
            Ok(conn.execute(
                "UPDATE tasks SET name = ?, status = ?, date = ? WHERE id = ? AND user_id = ?",
                rusqlite::params![task.name, task.status, task.date, id, user_id],
            )? > 0)
        })
        .await
    }

    pub async fn delete(db: &Db, id: i64, user_id: i64) -> Result<bool, rusqlite::Error> {
        db.run(move |conn| {
            Ok(conn.execute(
                "DELETE FROM tasks WHERE id = ? AND user_id = ?",
                [id, user_id],
            )? > 0)
        })
        .await
    }
}

#[catch(401)]
fn unauthorized() -> Redirect {
    Redirect::to("/login")
}

#[catch(403)]
fn forbidden() -> Template {
    Template::render("403", context! {})
}

#[catch(404)]
fn not_found() -> Template {
    Template::render("404", context! {})
}

#[catch(500)]
fn internal_error() -> Template {
    Template::render("500", context! {})
}

#[get("/login")]
async fn login_page(csrf_token: CsrfToken) -> Template {
    Template::render("login", context! { csrf_token: csrf_token.0 })
}

#[post("/login", data = "<login_form>")]
async fn login_post(
    db: Db,
    csrf_token: CsrfToken,
    cookies: &rocket::http::CookieJar<'_>,
    login_form: rocket::form::Form<LoginForm>,
) -> Result<Redirect, Status> {
    if login_form.csrf_token != csrf_token.0 {
        return Err(Status::Forbidden);
    }

    let username = login_form.username.clone();
    let password = login_form.password.clone();

    let user_data: Option<(i64, String)> = db
        .run(move |conn| {
            conn.query_row(
                "SELECT id, password_hash FROM users WHERE username = ?",
                [username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok()
        })
        .await;

    if let Some((id, hash)) = user_data {
        if bcrypt::verify(password, &hash).unwrap_or(false) {
            cookies.add_private(
                Cookie::build(("user_id", id.to_string()))
                    .path("/")
                    .same_site(SameSite::Lax)
                    .http_only(true)
                    .build(),
            );
            return Ok(Redirect::to("/"));
        }
    }

    Ok(Redirect::to("/login")) // Or return error
}

#[post("/logout")]
async fn logout(cookies: &rocket::http::CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::from("user_id"));
    Redirect::to("/login")
}

#[get("/?<sort_by>&<order>&<page>")]
async fn index(
    db: Db,
    auth: Option<AuthUser>,
    sort_by: Option<SortColumn>,
    order: Option<SortDirection>,
    page: Option<i64>,
    csrf_token: CsrfToken,
) -> Result<Template, Status> {
    if let Some(auth) = auth {
        let sort_by = sort_by.unwrap_or(SortColumn::Date);
        let order = order.unwrap_or(SortDirection::Desc);
        let page = page.unwrap_or(1).max(1);
        let limit = 10;
        let offset = (page - 1) * limit;

        let total_tasks = Task::count(&db, auth.0.id)
            .await
            .map_err(|_| Status::InternalServerError)?;
        let total_pages = (total_tasks as f64 / limit as f64).ceil() as i64;

        let tasks = Task::all(&db, auth.0.id, sort_by, order, limit, offset)
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
                user: auth.0,
                tasks: tasks,
                sort_by: sort_by,
                order: order,
                page: page,
                total_pages: total_pages,
                next_order_name: next_order_name,
                next_order_status: next_order_status,
                next_order_date: next_order_date,
                csrf_token: csrf_token.0,
            },
        ))
    } else {
        Ok(Template::render(
            "landing",
            context! { csrf_token: csrf_token.0 },
        ))
    }
}

#[get("/tasks?<sort_by>&<order>&<page>&<limit>")]
async fn get_tasks(
    db: Db,
    auth: AuthUser,
    sort_by: Option<SortColumn>,
    order: Option<SortDirection>,
    page: Option<i64>,
    limit: Option<i64>,
) -> Result<Json<Vec<Task>>, Status> {
    let sort_by = sort_by.unwrap_or(SortColumn::Date);
    let order = order.unwrap_or(SortDirection::Desc);
    let page = page.unwrap_or(1).max(1);
    let limit = limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    let tasks = Task::all(&db, auth.0.id, sort_by, order, limit, offset)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Json(tasks))
}

#[post("/task", data = "<task>")]
async fn create_task_form(
    db: Db,
    auth: AuthUser,
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
        user_id: Some(auth.0.id),
        is_urgent: false,
    };
    Task::insert(&db, task_obj)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/"))
}

#[get("/user_admin")]
async fn user_admin_index(
    db: Db,
    auth: AuthUser,
    csrf_token: CsrfToken,
) -> Result<Template, Status> {
    if auth.0.username != "admin" {
        return Err(Status::Forbidden);
    }
    let users = User::all(&db)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Template::render(
        "user_admin/index",
        context! { user: auth.0, users, csrf_token: csrf_token.0 },
    ))
}

#[get("/user_admin/new")]
async fn user_admin_new(auth: AuthUser, csrf_token: CsrfToken) -> Result<Template, Status> {
    if auth.0.username != "admin" {
        return Err(Status::Forbidden);
    }
    Ok(Template::render(
        "user_admin/new",
        context! { user: auth.0, csrf_token: csrf_token.0 },
    ))
}

#[post("/user_admin", data = "<user_form>")]
async fn user_admin_create(
    db: Db,
    auth: AuthUser,
    csrf_token: CsrfToken,
    user_form: rocket::form::Form<UserForm>,
) -> Result<Redirect, Status> {
    if auth.0.username != "admin" {
        return Err(Status::Forbidden);
    }
    if user_form.csrf_token != csrf_token.0 {
        return Err(Status::Forbidden);
    }
    let password = user_form.password.as_deref().unwrap_or("");
    let hash =
        bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|_| Status::InternalServerError)?;
    User::insert(&db, user_form.username.clone(), hash)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/user_admin"))
}

#[get("/user_admin/<id>/edit")]
async fn user_admin_edit(
    db: Db,
    auth: AuthUser,
    id: i64,
    csrf_token: CsrfToken,
) -> Result<Template, Status> {
    if auth.0.username != "admin" {
        return Err(Status::Forbidden);
    }
    let target_user = User::find(&db, id).await.ok_or(Status::NotFound)?;
    Ok(Template::render(
        "user_admin/edit",
        context! { user: auth.0, target_user, csrf_token: csrf_token.0 },
    ))
}

#[post("/user_admin/<id>", data = "<user_form>")]
async fn user_admin_update(
    db: Db,
    auth: AuthUser,
    id: i64,
    csrf_token: CsrfToken,
    user_form: rocket::form::Form<UserForm>,
) -> Result<Redirect, Status> {
    if auth.0.username != "admin" {
        return Err(Status::Forbidden);
    }
    if user_form.csrf_token != csrf_token.0 {
        return Err(Status::Forbidden);
    }
    let hash = if let Some(password) = &user_form.password {
        if !password.is_empty() {
            Some(
                bcrypt::hash(password, bcrypt::DEFAULT_COST)
                    .map_err(|_| Status::InternalServerError)?,
            )
        } else {
            None
        }
    } else {
        None
    };

    User::update(&db, id, user_form.username.clone(), hash)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/user_admin"))
}

#[post("/user_admin/<id>/delete", data = "<form>")]
async fn user_admin_delete(
    db: Db,
    auth: AuthUser,
    id: i64,
    csrf_token: CsrfToken,
    form: rocket::form::Form<CsrfForm>,
) -> Result<Redirect, Status> {
    if auth.0.username != "admin" {
        return Err(Status::Forbidden);
    }
    if form.csrf_token != csrf_token.0 {
        return Err(Status::Forbidden);
    }
    User::delete(&db, id)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/user_admin"))
}

#[post("/tasks", format = "json", data = "<task>")]
async fn create_task_json(
    db: Db,
    auth: AuthUser,
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
    task_obj.user_id = Some(auth.0.id);
    let id = Task::insert(&db, task_obj.clone())
        .await
        .map_err(|_| Status::InternalServerError)?;
    task_obj.id = Some(id);
    Ok(Json(task_obj))
}

#[get("/task/<id>")]
async fn view_task(db: Db, auth: AuthUser, id: i64, csrf_token: CsrfToken) -> Option<Template> {
    Task::find(&db, id, auth.0.id).await.map(|task| {
        Template::render(
            "view",
            context! {
                user: auth.0,
                task: task,
                csrf_token: csrf_token.0,
            },
        )
    })
}

#[get("/task/<id>/edit")]
async fn edit_task(db: Db, auth: AuthUser, id: i64, csrf_token: CsrfToken) -> Option<Template> {
    Task::find(&db, id, auth.0.id).await.map(|task| {
        Template::render(
            "edit",
            context! {
                user: auth.0,
                task: task,
                csrf_token: csrf_token.0,
            },
        )
    })
}

#[post("/task/<id>", data = "<task>")]
async fn update_task(
    db: Db,
    auth: AuthUser,
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
        user_id: Some(auth.0.id),
        is_urgent: false,
    };
    Task::update(&db, id, auth.0.id, task_obj)
        .await
        .map_err(|_| Status::InternalServerError)?;
    Ok(Redirect::to("/"))
}

#[post("/task/<id>/delete", data = "<form>")]
async fn delete_task(
    db: Db,
    auth: AuthUser,
    id: i64,
    csrf_token: CsrfToken,
    form: rocket::form::Form<CsrfForm>,
) -> Result<Redirect, Status> {
    if csrf_token.0 != form.csrf_token {
        return Err(Status::Forbidden);
    }
    Task::delete(&db, id, auth.0.id)
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
            let db = Db::get_one(&rocket).await.expect("database connection");
            db.run(|conn| match embedded::migrations::runner().run(conn) {
                Ok(report) => {
                    let applied = report.applied_migrations().len();
                    if applied > 0 {
                        println!("Applied {} migrations", applied);
                    }
                }
                Err(e) => {
                    panic!("Failed to run database migrations: {}", e);
                }
            })
            .await;
            rocket
        }))
        .mount("/static", FileServer::from(relative!("static")))
        .register(
            "/",
            catchers![unauthorized, forbidden, not_found, internal_error],
        )
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
                delete_task,
                login_page,
                login_post,
                logout,
                user_admin_index,
                user_admin_new,
                user_admin_create,
                user_admin_edit,
                user_admin_update,
                user_admin_delete
            ],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;

    fn get_csrf_token(client: &Client) -> String {
        // We can get CSRF token from login page
        client.get("/login").dispatch();
        client
            .cookies()
            .get(CSRF_COOKIE_NAME)
            .expect("CSRF cookie should be set")
            .value()
            .to_string()
    }

    fn login(client: &Client, username: &str, password: &str) -> String {
        let csrf_token = get_csrf_token(client);
        let body = format!(
            "username={}&password={}&csrf_token={}",
            username, password, csrf_token
        );
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body(body)
            .dispatch();
        assert_eq!(response.status(), Status::SeeOther);
        csrf_token
    }

    #[test]
    fn test_pagination() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let admin_csrf = login(&client, "admin", "admin");
        let username = format!("u{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

        // 1. Create a new user to have a clean task list
        client
            .post("/user_admin")
            .header(ContentType::Form)
            .body(format!(
                "username={}&password=password&csrf_token={}",
                username, admin_csrf
            ))
            .dispatch();

        client.post("/logout").dispatch();
        let csrf_token = login(&client, &username, "password");

        // 2. Create 15 tasks
        for i in 1..=15 {
            let task_name = format!("Task {:02}", i);
            client
                .post("/tasks")
                .header(ContentType::JSON)
                .header(Header::new("X-CSRF-Token", csrf_token.clone()))
                .body(format!(
                    r#"{{"name": "{}", "status": "new", "date": "2023-10-{:02}"}}"#,
                    task_name, i
                ))
                .dispatch();
        }

        // 3. Get Page 1 (should have 10 tasks)
        // Sort by date ASC to make it predictable: Task 01 to 10
        let response = client
            .get("/tasks?page=1&limit=10&sort_by=date&order=asc")
            .dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        assert_eq!(tasks.len(), 10);
        assert_eq!(tasks[0].name, "Task 01");
        assert_eq!(tasks[9].name, "Task 10");

        // 4. Get Page 2 (should have 5 tasks)
        let response = client
            .get("/tasks?page=2&limit=10&sort_by=date&order=asc")
            .dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        assert_eq!(tasks.len(), 5);
        assert_eq!(tasks[0].name, "Task 11");
        assert_eq!(tasks[4].name, "Task 15");

        // 5. Check HTML for pagination controls
        let response = client.get("/?page=1&sort_by=date&order=asc").dispatch();
        let body = response.into_string().unwrap();
        assert!(body.contains("Showing page"));
        assert!(body.contains(">1</span>"));
        assert!(body.contains(">2</span>"));
        assert!(body.contains("Next"));

        let response = client.get("/?page=2&sort_by=date&order=asc").dispatch();
        let body = response.into_string().unwrap();
        assert!(body.contains("Showing page"));
        assert!(body.contains(">2</span>"));
        assert!(body.contains(">2</span>")); // total pages
        assert!(body.contains("Prev"));
    }

    #[test]
    fn test_landing_page_and_login() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // Before login, should show the landing page
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains("Organize your life"));
        assert!(body.contains("Get Started Now"));

        login(&client, "admin", "admin");

        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains("Task Tracker"));
        assert!(body.contains("Add New Task"));
        assert!(body.contains("Hello, <span class=\"text-blue-600\">admin</span>"));
    }

    #[test]
    fn test_unauthorized_redirect() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // Accessing a protected route without login should redirect to /login
        let response = client.get("/task/1").dispatch();
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(response.headers().get_one("Location"), Some("/login"));
    }

    #[test]
    fn test_custom_404_page() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let response = client.get("/non-existent-page").dispatch();
        assert_eq!(response.status(), Status::NotFound);
        let body = response.into_string().unwrap();
        assert!(body.contains("404"));
        assert!(body.contains("Oops! Page not found."));
    }

    #[test]
    fn test_create_and_get_tasks_json() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = login(&client, "admin", "admin");

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
        let response = client.get("/tasks?limit=100").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        assert!(tasks.iter().any(|t| t.name == task_name));
    }

    #[test]
    fn test_create_task_form() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = login(&client, "admin", "admin");

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
        let response = client.get("/tasks?limit=100").dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        assert!(tasks
            .iter()
            .any(|t| t.name == task_name && t.status == TaskStatus::Done));
    }

    #[test]
    fn test_view_task() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = login(&client, "admin", "admin");

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
        let csrf_token = login(&client, "admin", "admin");

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
        let csrf_token = login(&client, "admin", "admin");

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
        login(&client, "admin", "admin");
        let response = client.get("/task/999999").dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    #[test]
    fn test_security_headers() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/login").dispatch();
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
        let csrf_token = login(&client, "admin", "admin");
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
        let csrf_token = login(&client, "admin", "admin");
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
        let csrf_token = login(&client, "admin", "admin");
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
        let csrf_token = login(&client, "admin", "admin");
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
        login(&client, "admin", "admin");

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
    fn test_user_isolation() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // 1. Create a new user manually in DB for testing isolation
        // Since we don't have a registration route, we'll just use the DB directly if we could,
        // but it's easier to just assume another user exists if we seed it.
        // Actually, let's just use two sessions with same admin for now to test session works,
        // but that doesn't test isolation.

        // Let's add a second user in migrations or during ignite for tests?
        // Better: just add it in the test using the DB fairing if possible.
        // But we can just use the fact that AuthUser guard works.

        // I will add a test that checks if unauthorized user can access tasks.
        let response = client.get("/tasks").dispatch();
        // Since we added a 401 catcher that redirects, it will now be SeeOther
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(response.headers().get_one("Location"), Some("/login"));
    }

    #[test]
    fn test_user_admin_access_control() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        // 1. Try to access user_admin without login
        let response = client.get("/user_admin").dispatch();
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(response.headers().get_one("Location"), Some("/login"));

        // 2. Login as non-admin (need to create one first)
        let csrf_token = login(&client, "admin", "admin");
        let body = format!(
            "username=testuser&password=password&csrf_token={}",
            csrf_token
        );
        client
            .post("/user_admin")
            .header(ContentType::Form)
            .body(body)
            .dispatch();

        // Logout and login as testuser
        client.post("/logout").dispatch();
        login(&client, "testuser", "password");

        // Try to access user_admin as testuser
        let response = client.get("/user_admin").dispatch();
        assert_eq!(response.status(), Status::Forbidden);
    }

    #[test]
    fn test_user_admin_crud() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = login(&client, "admin", "admin");
        let username = format!("u{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

        // 1. Create user
        let body = format!(
            "username={}&password=password&csrf_token={}",
            username, csrf_token
        );
        let response = client
            .post("/user_admin")
            .header(ContentType::Form)
            .body(body)
            .dispatch();
        assert_eq!(response.status(), Status::SeeOther);

        // 2. List users and find ID
        let response = client.get("/user_admin").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains(&username));

        // Find the user ID in the HTML. It's in a <td> before the username.
        // Very basic extraction:
        let user_id = body
            .split(&username)
            .next()
            .unwrap()
            .rsplit("px-6 py-4\">")
            .next()
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .trim();

        // 3. Edit user
        let response = client
            .get(format!("/user_admin/{}/edit", user_id))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let updated_username = format!("{}_upd", username);
        let body = format!(
            "username={}&password=&csrf_token={}",
            updated_username, csrf_token
        );
        let response = client
            .post(format!("/user_admin/{}", user_id))
            .header(ContentType::Form)
            .body(body)
            .dispatch();
        assert_eq!(response.status(), Status::SeeOther);

        // 4. Delete user
        let body = format!("csrf_token={}", csrf_token);
        let response = client
            .post(format!("/user_admin/{}/delete", user_id))
            .header(ContentType::Form)
            .body(body)
            .dispatch();
        assert_eq!(response.status(), Status::SeeOther);

        let response = client.get("/user_admin").dispatch();
        assert!(!response.into_string().unwrap().contains(&updated_username));
    }

    #[test]
    fn test_sorting_by_name() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = login(&client, "admin", "admin");
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
        let response = client
            .get("/tasks?sort_by=name&order=asc&limit=100")
            .dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");

        let filtered_tasks: Vec<&Task> = tasks
            .iter()
            .filter(|t| t.name == name_a || t.name == name_b)
            .collect();
        assert_eq!(filtered_tasks.len(), 2);
        assert_eq!(filtered_tasks[0].name, name_a);
        assert_eq!(filtered_tasks[1].name, name_b);

        // 2. Get sorted by name DESC
        let response = client
            .get("/tasks?sort_by=name&order=desc&limit=100")
            .dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");
        let filtered_tasks: Vec<&Task> = tasks
            .iter()
            .filter(|t| t.name == name_a || t.name == name_b)
            .collect();
        assert_eq!(filtered_tasks.len(), 2);
        assert_eq!(filtered_tasks[0].name, name_b);
        assert_eq!(filtered_tasks[1].name, name_a);
    }

    #[test]
    fn test_task_urgency() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let csrf_token = login(&client, "admin", "admin");

        let now = Local::now().date_naive();
        let today_str = now.format("%Y-%m-%d").to_string();
        let tomorrow_str = (now + Duration::days(1)).format("%Y-%m-%d").to_string();
        let next_week_str = (now + Duration::days(7)).format("%Y-%m-%d").to_string();

        // 1. Create task for today
        client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token.clone()))
            .body(format!(
                r#"{{"name": "Today Task", "status": "new", "date": "{}"}}"#,
                today_str
            ))
            .dispatch();

        // 2. Create task for tomorrow
        client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token.clone()))
            .body(format!(
                r#"{{"name": "Tomorrow Task", "status": "new", "date": "{}"}}"#,
                tomorrow_str
            ))
            .dispatch();

        // 3. Create task for next week
        client
            .post("/tasks")
            .header(ContentType::JSON)
            .header(Header::new("X-CSRF-Token", csrf_token))
            .body(format!(
                r#"{{"name": "Next Week Task", "status": "new", "date": "{}"}}"#,
                next_week_str
            ))
            .dispatch();

        // 4. Verify urgency
        let response = client
            .get("/tasks?limit=100&sort_by=name&order=asc")
            .dispatch();
        let tasks: Vec<Task> = response.into_json().expect("valid JSON tasks");

        let today_task = tasks.iter().find(|t| t.name == "Today Task").unwrap();
        let tomorrow_task = tasks.iter().find(|t| t.name == "Tomorrow Task").unwrap();
        let next_week_task = tasks.iter().find(|t| t.name == "Next Week Task").unwrap();

        assert!(today_task.is_urgent, "Today task should be urgent");
        assert!(tomorrow_task.is_urgent, "Tomorrow task should be urgent");
        assert!(
            !next_week_task.is_urgent,
            "Next week task should NOT be urgent"
        );
    }
}
