//! D23-T10: org chart drafts. A person (or an agent through
//! `sales.orgchart.propose`) asks for proposals for an account; a job reads
//! the account's contacts the requester may read and writes **open drafts**
//! (`sales_orgchart_draft`) of who each unplaced person probably reports to
//! and, where it is missing, their department. Nothing changes a contact
//! until a person accepts a draft ([`decide`]), which sets the manager
//! through the ordinary manager change (D23-T4: access, group and loop
//! checks, If-Match, audit); rejecting only marks the draft.
//!
//! **How links are proposed** ([`propose_links`], pure): from job titles
//! and departments, in English and Arabic, with no model. A title has a
//! seniority ([`title_rank`]): chief and managing director, vice
//! president, director and head, manager and lead, everyone else. An
//! unplaced, current person's proposed manager is the closest more senior
//! person in the same department; with no one there, the single most
//! senior person at the account when they outrank them. Signatures and
//! enrichment (the other two `source` values) wait for stored signatures
//! and D24's people data; no record text is sent to a model.

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job that writes an account's drafts.
pub const JOB: &str = "sales_orgchart_draft";
/// Contacts an account's proposal reads.
const MAX_PEOPLE: i64 = 500;

/// One person as the proposer sees them. Pure data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub id: Uuid,
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub reports_to: Option<Uuid>,
    pub is_former: bool,
}

/// One proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub contact: Uuid,
    pub manager: Option<Uuid>,
    pub department: Option<String>,
    pub reason: String,
}

/// A title's seniority, higher is more senior: 5 chief or managing
/// director, 4 vice president, 3 director or head, 2 manager or lead, 1
/// anyone else, `None` for no title. Pure.
pub fn title_rank(title: Option<&str>) -> Option<u8> {
    let t = title?.trim().to_lowercase();
    if t.is_empty() {
        return None;
    }
    // Abbreviations match whole words ("cto" is inside "director").
    let words: Vec<&str> = t.split(|c: char| !c.is_alphanumeric()).collect();
    let word = |list: &[&str]| list.iter().any(|w| words.contains(w));
    let phrase = |list: &[&str]| list.iter().any(|w| t.contains(w));
    let deputy = phrase(&["vice president", "نائب"]);
    let rank = if !deputy
        && (word(&["ceo", "cfo", "coo", "cto", "cio", "chairman", "founder"])
            || phrase(&[
                "chief",
                "president",
                "managing director",
                "general manager",
                "الرئيس التنفيذي",
                "المدير العام",
                "مدير عام",
                "رئيس مجلس",
            ])) {
        5
    } else if deputy || word(&["vp", "svp", "evp"]) {
        4
    } else if word(&["director"]) || phrase(&["head of", "مدير إدارة", "مدير ادارة", "رئيس قسم"])
    {
        3
    } else if word(&["manager", "lead", "supervisor"]) || phrase(&["مدير", "مشرف", "قائد"])
    {
        2
    } else {
        1
    };
    Some(rank)
}

fn same_department(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.trim().eq_ignore_ascii_case(b.trim()) && !a.trim().is_empty(),
        _ => false,
    }
}

/// The proposals for an account's people; see the module doc. Pure.
pub fn propose_links(people: &[Person]) -> Vec<Proposal> {
    let current: Vec<&Person> = people.iter().filter(|p| !p.is_former).collect();
    // The single most senior person, when there is exactly one.
    let top_rank = current
        .iter()
        .filter_map(|p| title_rank(p.job_title.as_deref()))
        .max();
    let tops: Vec<&&Person> = current
        .iter()
        .filter(|p| top_rank.is_some() && title_rank(p.job_title.as_deref()) == top_rank)
        .collect();
    let top = (tops.len() == 1).then(|| tops[0]);
    let mut out = Vec::new();
    for p in &current {
        if p.reports_to.is_some() {
            continue;
        }
        let rank = title_rank(p.job_title.as_deref()).unwrap_or(1);
        let mut in_dept: Vec<(&&Person, u8)> = current
            .iter()
            .filter(|q| q.id != p.id)
            .filter(|q| same_department(p.department.as_deref(), q.department.as_deref()))
            .filter_map(|q| title_rank(q.job_title.as_deref()).map(|r| (q, r)))
            .filter(|(_, r)| *r > rank)
            .collect();
        in_dept.sort_by_key(|(q, r)| (*r, q.id));
        let (manager, reason) = match in_dept.first() {
            Some((q, _)) => (
                Some(q.id),
                "the closest more senior title in the same department".to_owned(),
            ),
            None => match top {
                Some(t) if t.id != p.id && top_rank.is_some_and(|r| r > rank) => (
                    Some(t.id),
                    "the most senior title at the account".to_owned(),
                ),
                _ => (None, String::new()),
            },
        };
        let department = match (p.department.as_deref(), manager) {
            (None | Some(""), Some(m)) => current
                .iter()
                .find(|q| q.id == m)
                .and_then(|q| q.department.clone())
                .filter(|d| !d.trim().is_empty()),
            _ => None,
        };
        if manager.is_some() || department.is_some() {
            out.push(Proposal {
                contact: p.id,
                manager,
                department,
                reason,
            });
        }
    }
    out
}

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftJob {
    pub account_id: Uuid,
    /// Whose access the proposal reads with, and who owns the drafts.
    pub user_id: Uuid,
}

/// Queues the proposal for `account` as `ctx`'s user.
pub async fn queue_propose(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
) -> Result<(), AppError> {
    attome_records::entity_crud::read_record(state, ctx, "account", account).await?;
    let job = attome_core::jobs::JOB_TYPES
        .job(
            JOB,
            &DraftJob {
                account_id: account,
                user_id: ctx.user_id,
            },
        )
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

fn text(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.trim().is_empty())
}

fn uuid(data: &Value, key: &str) -> Option<Uuid> {
    data.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Writes open drafts for the account's people `ctx` may read; never
/// changes a contact. Answers the drafts written. A person who already has
/// an open draft gets no second one.
pub async fn propose(
    state: &EngineState,
    ctx: &SecurityContext,
    account: Uuid,
) -> Result<usize, AppError> {
    attome_records::entity_crud::read_record(state, ctx, "account", account).await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM contact WHERE account_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $2",
    )
    .bind(account)
    .bind(MAX_PEOPLE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut people = Vec::new();
    let mut names: HashMap<Uuid, String> = HashMap::new();
    for id in ids {
        let Ok(record) = attome_records::entity_crud::read_record(state, ctx, "contact", id).await
        else {
            continue;
        };
        let data = record.data();
        if let Some(name) = text(data, "full_name") {
            names.insert(id, name);
        }
        people.push(Person {
            id,
            job_title: text(data, "job_title"),
            department: text(data, "department"),
            reports_to: uuid(data, "reports_to"),
            is_former: data.get("is_former_employee").and_then(Value::as_bool) == Some(true),
        });
    }
    let open: HashSet<Uuid> = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT contact_ref FROM sales_orgchart_draft \
          WHERE account_ref = $1 AND status = 'open' AND (is_active IS NULL OR is_active = true)",
    )
    .bind(account)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .flatten()
    .collect();
    let mut written = 0;
    for proposal in propose_links(&people) {
        if open.contains(&proposal.contact) {
            continue;
        }
        let name = names
            .get(&proposal.contact)
            .cloned()
            .unwrap_or_else(|| proposal.contact.to_string());
        let mut body = json!({
            "name": name,
            "account_ref": account.to_string(),
            "contact_ref": proposal.contact.to_string(),
            "source": "title",
            "status": "open",
            "reason": proposal.reason,
        });
        if let Some(manager) = proposal.manager {
            body["proposed_manager_ref"] = json!(manager.to_string());
        }
        if let Some(department) = &proposal.department {
            body["proposed_department"] = json!(department);
        }
        attome_records::entity_crud::create_record_for(
            state,
            ctx,
            ctx.user_id,
            "sales_orgchart_draft",
            body,
        )
        .await?;
        written += 1;
    }
    Ok(written)
}

/// What deciding a draft did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesOrgChartDraftDecided {
    pub draft_id: Uuid,
    /// `accepted` or `rejected`.
    pub status: String,
    /// The contact's manager before an accepted draft set it (to undo).
    pub previous_manager_id: Option<Uuid>,
}

/// Accepts (sets the manager and, when proposed, the department) or
/// rejects an open draft, as `ctx`.
pub async fn decide(
    state: &EngineState,
    ctx: &SecurityContext,
    draft: Uuid,
    accept: bool,
) -> Result<SalesOrgChartDraftDecided, AppError> {
    let record =
        attome_records::entity_crud::read_record(state, ctx, "sales_orgchart_draft", draft).await?;
    let data = record.data();
    if text(data, "status").as_deref() != Some("open") {
        return Err(AppError::Conflict("this draft has been decided"));
    }
    let contact = uuid(data, "contact_ref").ok_or(AppError::NotFound)?;
    let mut previous = None;
    if accept {
        let person =
            attome_records::entity_crud::read_record(state, ctx, "contact", contact).await?;
        if let Some(manager) = uuid(data, "proposed_manager_ref") {
            let set = super::set_manager(
                state,
                ctx,
                contact,
                Some(manager),
                super::ManagerLine::Solid,
                person.row_version(),
            )
            .await?;
            previous = set.previous_manager_id;
        }
        if let Some(department) = text(data, "proposed_department") {
            let current =
                attome_records::entity_crud::read_record(state, ctx, "contact", contact).await?;
            attome_records::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                "contact",
                contact,
                current.row_version(),
                json!({ "department": department }),
            )
            .await?;
        }
    }
    let status = if accept { "accepted" } else { "rejected" };
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "sales_orgchart_draft",
        draft,
        record.row_version(),
        json!({
            "status": status,
            "decided_by": ctx.user_id.to_string(),
            "decided_at": chrono::Utc::now().date_naive().to_string(),
        }),
    )
    .await?;
    Ok(SalesOrgChartDraftDecided {
        draft_id: draft,
        status: status.to_owned(),
        previous_manager_id: previous,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(n: u128, title: &str, dept: &str) -> Person {
        Person {
            id: Uuid::from_u128(n),
            job_title: (!title.is_empty()).then(|| title.to_owned()),
            department: (!dept.is_empty()).then(|| dept.to_owned()),
            reports_to: None,
            is_former: false,
        }
    }

    #[test]
    fn titles_rank_in_english_and_arabic() {
        assert_eq!(title_rank(Some("Chief Executive Officer")), Some(5));
        assert_eq!(title_rank(Some("Vice President, Sales")), Some(4));
        assert_eq!(title_rank(Some("Head of Procurement")), Some(3));
        assert_eq!(title_rank(Some("Sales Director")), Some(3), "not cto");
        assert_eq!(title_rank(Some("Sales Manager")), Some(2));
        assert_eq!(title_rank(Some("Engineer")), Some(1));
        assert_eq!(title_rank(Some("الرئيس التنفيذي")), Some(5));
        assert_eq!(title_rank(Some("مدير المبيعات")), Some(2));
        assert_eq!(title_rank(None), None);
    }

    #[test]
    fn the_closest_senior_in_the_department_is_proposed() {
        let ceo = person(1, "CEO", "");
        let director = person(2, "Sales Director", "Sales");
        let manager = person(3, "Sales Manager", "Sales");
        let rep = person(4, "Account Executive", "Sales");
        let engineer = person(5, "Engineer", "");
        let proposals = propose_links(&[ceo, director, manager, rep, engineer]);
        let to = |n: u128| {
            proposals
                .iter()
                .find(|p| p.contact == Uuid::from_u128(n))
                .and_then(|p| p.manager)
        };
        assert_eq!(to(4), Some(Uuid::from_u128(3)), "rep to the manager");
        assert_eq!(to(3), Some(Uuid::from_u128(2)), "manager to the director");
        assert_eq!(to(2), Some(Uuid::from_u128(1)), "director to the CEO");
        assert_eq!(
            to(5),
            Some(Uuid::from_u128(1)),
            "no department: the top person"
        );
        assert_eq!(to(1), None, "the CEO reports to no one here");
    }

    #[test]
    fn placed_and_former_people_get_no_draft() {
        let mut placed = person(2, "Engineer", "IT");
        placed.reports_to = Some(Uuid::from_u128(1));
        let mut former = person(3, "Engineer", "IT");
        former.is_former = true;
        let proposals = propose_links(&[person(1, "CTO", "IT"), placed, former]);
        assert!(proposals.is_empty(), "{proposals:?}");
    }
}
