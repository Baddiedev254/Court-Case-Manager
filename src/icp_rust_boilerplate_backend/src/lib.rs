#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use regex::Regex;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct UserProfile {
    id: u64,
    username: String,
    email: String,
    password: String, // Store hashed passwords
    role: UserRole,
    created_at: u64,
}

#[derive(
    candid::CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default, Debug,
)]
enum UserRole {
    #[default]
    Judge,
    Lawyer,
    CourtStaff,
    Litigant,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Case {
    id: u64,
    case_number: String,
    title: String,
    description: String,
    status: CaseStatus,
    judge_id: u64,
    lawyer_ids: Vec<u64>,
    created_at: u64,
}

#[derive(
    candid::CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default, Debug,
)]
enum CaseStatus {
    #[default]
    Pending,
    Ongoing,
    Closed,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Hearing {
    id: u64,
    case_id: u64,
    judge_id: u64,
    date: u64,
    location: String,
    description: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Document {
    id: u64,
    case_id: u64,
    title: String,
    description: String,
    file: Vec<u8>,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Message {
    id: u64,
    case_id: u64,
    sender_id: u64,
    recipient_id: u64,
    content: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Notification {
    id: u64,
    user_id: u64,
    message: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct AuditLog {
    id: u64,
    action: String,
    user_id: u64,
    timestamp: u64,
}

impl Storable for UserProfile {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for UserProfile {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Case {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Case {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Hearing {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Hearing {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Document {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Document {
    const MAX_SIZE: u32 = 4096;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Message {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Message {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Notification {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Notification {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for AuditLog {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for AuditLog {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static USERS_STORAGE: RefCell<StableBTreeMap<u64, UserProfile, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static CASES_STORAGE: RefCell<StableBTreeMap<u64, Case, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static HEARINGS_STORAGE: RefCell<StableBTreeMap<u64, Hearing, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static DOCUMENTS_STORAGE: RefCell<StableBTreeMap<u64, Document, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));

    static MESSAGES_STORAGE: RefCell<StableBTreeMap<u64, Message, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));

    static NOTIFICATIONS_STORAGE: RefCell<StableBTreeMap<u64, Notification, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6)))
    ));

    static AUDIT_LOGS_STORAGE: RefCell<StableBTreeMap<u64, AuditLog, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(7)))
    ));
}

// User Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct UserPayload {
    username: String,
    email: String,
    password: String,
    role: UserRole,
}

// Case Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct CasePayload {
    case_number: String,
    title: String,
    description: String,
    judge_id: u64,
    lawyer_ids: Vec<u64>,
    password: String,
}

// Hearing Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct HearingPayload {
    case_id: u64,
    judge_id: u64,
    password: String,
    date: u64,
    location: String,
    description: String,
}

// Document Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct DocumentPayload {
    case_id: u64,
    title: String,
    description: String,
    file: Vec<u8>,
}

// Message Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct MessagePayload {
    case_id: u64,
    sender_id: u64,
    recipient_id: u64,
    content: String,
}

// Helper function to hash passwords
fn hash_password(password: &str) -> String {
    // Reverse the password string
    let reversed: String = password.chars().rev().collect();

    // Convert to uppercase
    let uppercased = reversed.to_uppercase();

    // Add a simple prefix and suffix
    format!("hashed_{}_secure", uppercased)
}

// Helper function to verify passwords (simplified)
fn verify_password(password: &str, hashed: &str) -> bool {
    hashed == hash_password(password)
}

// Helper function to validate passwords
fn validate_password(password: &str) -> Result<(), String> {
    let min_length = 8;
    let has_uppercase = Regex::new(r"[A-Z]").unwrap();
    let has_lowercase = Regex::new(r"[a-z]").unwrap();
    let has_digit = Regex::new(r"\d").unwrap();
    let has_special_char = Regex::new(r"[^A-Za-z0-9]").unwrap();

    if password.len() < min_length {
        return Err("Password must be at least 8 characters long".to_string());
    }

    if !has_uppercase.is_match(password) {
        return Err("Password must contain at least one uppercase letter".to_string());
    }

    if !has_lowercase.is_match(password) {
        return Err("Password must contain at least one lowercase letter".to_string());
    }

    if !has_digit.is_match(password) {
        return Err("Password must contain at least one digit".to_string());
    }

    if !has_special_char.is_match(password) {
        return Err("Password must contain at least one special character".to_string());
    }

    Ok(())
}

// Function to create a new user
#[ic_cdk::update]
fn create_user(payload: UserPayload) -> Result<UserProfile, String> {
    // Validate payload to ensure required fields are present and are not empty
    if payload.username.is_empty() || payload.email.is_empty() || payload.password.is_empty() {
        return Err("Username, email, and password are required".to_string());
    }

    // Ensure the password satisfies the password requirements
    validate_password(&payload.password)?;

    // Validate the email address format
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err("Invalid email address".to_string());
    }

    // Ensure the email address is unique
    let email_exists = USERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.email == payload.email)
    });
    if email_exists {
        return Err("Email address already exists, use another email".to_string());
    }

    // Validate the username to ensure it is unique
    let username_exists = USERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.username == payload.username)
    });
    if username_exists {
        return Err("Username already exists, use another username".to_string());
    }

    // Increment the ID counter and create a new user profile
    let id = increment_id_counter()?;

    let user_profile = UserProfile {
        id,
        username: payload.username,
        email: payload.email,
        password: hash_password(&payload.password),
        role: payload.role,
        created_at: current_time(),
    };

    USERS_STORAGE.with(|storage| storage.borrow_mut().insert(id, user_profile.clone()));

    Ok(user_profile)
}

// Function to create a new case
#[ic_cdk::update]
fn create_case(payload: CasePayload) -> Result<Case, String> {
    // Validate payload to ensure required fields are present and are not empty
    if payload.case_number.is_empty() || payload.title.is_empty() || payload.description.is_empty() {
        return Err("Case number, title, and description are required".to_string());
    }

    // Ensure only the judge can create a case
    if !is_user_judge(payload.judge_id) {
        return Err("Only a judge can create a case".to_string());
    }

    // Verify the password for the judge
    if !verify_user_password(payload.judge_id, &payload.password) {
        return Err("Invalid password".to_string());
    }

    // Ensure the lawyer IDs are valid
    if !are_lawyer_ids_valid(&payload.lawyer_ids) {
        return Err("Invalid lawyer ID(s)".to_string());
    }

    let id = increment_id_counter()?;

    let case = Case {
        id,
        case_number: payload.case_number,
        title: payload.title,
        description: payload.description,
        status: CaseStatus::Pending,
        judge_id: payload.judge_id,
        lawyer_ids: payload.lawyer_ids,
        created_at: current_time(),
    };

    CASES_STORAGE.with(|storage| storage.borrow_mut().insert(id, case.clone()));

    // Log audit
    log_audit("Create case", payload.judge_id, case.id);

    Ok(case)
}

// Function to get all cases
#[ic_cdk::query]
fn get_cases() -> Result<Vec<Case>, String> {
    CASES_STORAGE.with(|storage| {
        let cases: Vec<Case> = storage
            .borrow()
            .iter()
            .map(|(_, case)| case.clone())
            .collect();

        if cases.is_empty() {
            Err("No cases found".to_string())
        } else {
            Ok(cases)
        }
    })
}

// Function to create a new hearing
#[ic_cdk::update]
fn create_hearing(payload: HearingPayload) -> Result<Hearing, String> {
    // Validate payload to ensure required fields are present and are not empty
    if payload.location.is_empty() || payload.description.is_empty() {
        return Err("Location and description are required".to_string());
    }

    // Ensure only the judge can create a hearing
    if !is_user_judge(payload.judge_id) {
        return Err("Only a judge can create a hearing".to_string());
    }

    // Verify the password for the judge
    if !verify_user_password(payload.judge_id, &payload.password) {
        return Err("Invalid password".to_string());
    }

    // Ensure the case ID is valid
    if !is_case_id_valid(payload.case_id) {
        return Err("Invalid case ID".to_string());
    }

    let id = increment_id_counter()?;

    let hearing = Hearing {
        id,
        case_id: payload.case_id,
        judge_id: payload.judge_id,
        date: payload.date,
        location: payload.location,
        description: payload.description,
        created_at: current_time(),
    };

    HEARINGS_STORAGE.with(|storage| storage.borrow_mut().insert(id, hearing.clone()));

    // Notify users about the hearing
    notify_users(hearing.case_id, format!("New hearing scheduled at {}", hearing.location));

    Ok(hearing)
}

// Function to get all hearings
#[ic_cdk::query]
fn get_hearings() -> Result<Vec<Hearing>, String> {
    HEARINGS_STORAGE.with(|storage| {
        let hearings: Vec<Hearing> = storage
            .borrow()
            .iter()
            .map(|(_, hearing)| hearing.clone())
            .collect();

        if hearings.is_empty() {
            Err("No hearings found".to_string())
        } else {
            Ok(hearings)
        }
    })
}

// Function to create a new document
#[ic_cdk::update]
fn create_document(payload: DocumentPayload) -> Result<Document, String> {
    // Validate payload to ensure required fields are present and are not empty
    if payload.title.is_empty() || payload.file.is_empty() {
        return Err("Title and file are required".to_string());
    }

    // Ensure the case ID is valid
    if !is_case_id_valid(payload.case_id) {
        return Err("Invalid case ID".to_string());
    }

    // Ensure the user is authorized to upload a document
    if !is_user_lawyer(payload.case_id) {
        return Err("Only a lawyer can upload a document".to_string());
    }

    let id = increment_id_counter()?;

    let document = Document {
        id,
        case_id: payload.case_id,
        title: payload.title,
        description: payload.description,
        file: payload.file,
        created_at: current_time(),
    };

    DOCUMENTS_STORAGE.with(|storage| storage.borrow_mut().insert(id, document.clone()));

    // Log audit
    log_audit("Create document", payload.case_id, document.id);

    // Notify users about the new document
    notify_users(document.case_id, format!("New document uploaded: {}", document.title));

    Ok(document)
}

// Function to get all documents
#[ic_cdk::query]
fn get_documents() -> Result<Vec<Document>, String> {
    DOCUMENTS_STORAGE.with(|storage| {
        let documents: Vec<Document> = storage
            .borrow()
            .iter()
            .map(|(_, document)| document.clone())
            .collect();

        if documents.is_empty() {
            Err("No documents found".to_string())
        } else {
            Ok(documents)
        }
    })
}

// Function to create a new message
#[ic_cdk::update]
fn send_message(payload: MessagePayload) -> Result<Message, String> {
    if payload.content.is_empty() {
        return Err("Content is required".to_string());
    }

    let id = increment_id_counter()?;

    let message = Message {
        id,
        case_id: payload.case_id,
        sender_id: payload.sender_id,
        recipient_id: payload.recipient_id,
        content: payload.content,
        created_at: current_time(),
    };

    MESSAGES_STORAGE.with(|storage| storage.borrow_mut().insert(id, message.clone()));

    // Log audit
    log_audit("Send message", payload.sender_id, message.id);

    // Notify recipient about the new message
    notify_user(message.recipient_id, format!("New message: {}", message.content));

    Ok(message)
}

// Helper function to log audits
fn log_audit(action: &str, user_id: u64, entity_id: u64) {
    let id = increment_id_counter().expect("Cannot increment ID counter");

    let audit_log = AuditLog {
        id,
        action: action.to_string(),
        user_id,
        timestamp: current_time(),
    };

    AUDIT_LOGS_STORAGE.with(|storage| storage.borrow_mut().insert(id, audit_log));
}

// Helper function to notify users about case updates
fn notify_users(case_id: u64, message: String) {
    let case = CASES_STORAGE.with(|storage| storage.borrow().get(&case_id).as_ref().cloned());
    if let Some(case) = case {
        let user_ids: Vec<u64> = vec![case.judge_id]
            .into_iter()
            .chain(case.lawyer_ids.into_iter())
            .collect();
        for user_id in user_ids {
            notify_user(user_id, message.clone());
        }
    }
}

// Helper function to notify a single user
fn notify_user(user_id: u64, message: String) {
    let id = increment_id_counter().expect("Cannot increment ID counter");

    let notification = Notification {
        id,
        user_id,
        message,
        created_at: current_time(),
    };

    NOTIFICATIONS_STORAGE.with(|storage| storage.borrow_mut().insert(id, notification));
}

// Helper function to check if a user is a judge
fn is_user_judge(user_id: u64) -> bool {
    USERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.id == user_id && user.role == UserRole::Judge)
    })
}

// Helper function to verify user's password
fn verify_user_password(user_id: u64, password: &str) -> bool {
    USERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.id == user_id)
            .map(|(_, user)| verify_password(password, &user.password))
            .unwrap_or(false)
    })
}

// Helper function to check if lawyer IDs are valid
fn are_lawyer_ids_valid(lawyer_ids: &[u64]) -> bool {
    USERS_STORAGE.with(|storage| {
        lawyer_ids.iter().all(|&lawyer_id| {
            storage
                .borrow()
                .iter()
                .any(|(_, user)| user.id == lawyer_id && user.role == UserRole::Lawyer)
        })
    })
}

// Helper function to check if a user is a lawyer
fn is_user_lawyer(user_id: u64) -> bool {
    USERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.id == user_id && user.role == UserRole::Lawyer)
    })
}

// Helper function to check if a case ID is valid
fn is_case_id_valid(case_id: u64) -> bool {
    CASES_STORAGE.with(|storage| storage.borrow().contains_key(&case_id))
}

// Helper function to increment ID counter
fn increment_id_counter() -> Result<u64, String> {
    ID_COUNTER.with(|counter: &RefCell<IdCell>| {
        let current_value = *counter.borrow().get();
        counter.borrow_mut().set(current_value + 1).map_err(|e| format!("Failed to set ID counter: {:?}", e))?;
        Ok(current_value + 1)
    })
}



// Error types
#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    Unauthorized { msg: String },
}

// Helper function to get the current time
fn current_time() -> u64 {
    time()
}

// Export candid
ic_cdk::export_candid!();
