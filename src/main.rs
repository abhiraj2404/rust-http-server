use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder, Result};
use serde::{Deserialize, Serialize};
use solana_sdk::{signature::{Keypair, Signer}, pubkey::Pubkey};
use std::sync::Arc;
use spl_token::instruction as token_instruction;
use solana_sdk::signature::{Signature, read_keypair_file};
use solana_sdk::message::Message;
use solana_sdk::signer::keypair::keypair_from_seed;
use solana_sdk::signer::SignerError;
use std::str::FromStr;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

// --- Keypair Endpoint ---
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> impl Responder {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    let data = KeypairData { pubkey, secret };
    HttpResponse::Ok().json(SuccessResponse { success: true, data })
}

// --- Token Create Endpoint ---
#[derive(Deserialize)]
struct TokenCreateRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaData {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenCreateData {
    program_id: String,
    accounts: Vec<AccountMetaData>,
    instruction_data: String,
}

async fn create_token(req: web::Json<TokenCreateRequest>) -> impl Responder {
    use solana_sdk::pubkey::Pubkey;
    use spl_token::id as spl_token_program_id;
    use spl_token::instruction::initialize_mint;
    use solana_sdk::instruction::Instruction;
    use solana_sdk::instruction::AccountMeta;
    use std::str::FromStr;

    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid mint pubkey".to_string(),
            });
        }
    };
    let mint_authority = match Pubkey::from_str(&req.mintAuthority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid mintAuthority pubkey".to_string(),
            });
        }
    };
    // For simplicity, freeze_authority is set to None
    let decimals = req.decimals;
    let instruction = match initialize_mint(
        &spl_token_program_id(),
        &mint,
        &mint_authority,
        None,
        decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: format!("Failed to create initialize_mint instruction: {}", e),
            });
        }
    };
    let accounts_serialized = instruction
        .accounts
        .iter()
        .map(|meta| AccountMetaData {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();
    let data = TokenCreateData {
        program_id: instruction.program_id.to_string(),
        accounts: accounts_serialized,
        instruction_data: base64::encode(&instruction.data),
    };
    HttpResponse::Ok().json(SuccessResponse { success: true, data })
}

// --- Mint Token Endpoint ---
#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(req: web::Json<MintTokenRequest>) -> impl Responder {
    use spl_token::instruction::mint_to;
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid mint pubkey".to_string() }),
    };
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid destination pubkey".to_string() }),
    };
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid authority pubkey".to_string() }),
    };
    let instruction = match mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: format!("Failed to create mint_to instruction: {}", e) }),
    };
    let accounts_serialized = instruction.accounts.iter().map(|meta| AccountMetaData {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let data = TokenCreateData {
        program_id: instruction.program_id.to_string(),
        accounts: accounts_serialized,
        instruction_data: base64::encode(&instruction.data),
    };
    HttpResponse::Ok().json(SuccessResponse { success: true, data })
}

// --- Sign Message Endpoint ---
#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> impl Responder {
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Missing required fields".to_string() });
    }
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid secret key encoding".to_string() }),
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid secret key bytes".to_string() }),
    };
    let signature = keypair.sign_message(req.message.as_bytes());
    let data = SignMessageData {
        signature: base64::encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: req.message.clone(),
    };
    HttpResponse::Ok().json(SuccessResponse { success: true, data })
}

// --- Verify Message Endpoint ---
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> impl Responder {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Missing required fields".to_string() });
    }
    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid pubkey encoding".to_string() }),
    };
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid signature encoding".to_string() }),
    };
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid signature bytes".to_string() }),
    };
    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());
    let data = VerifyMessageData {
        valid,
        message: req.message.clone(),
        pubkey: pubkey.to_string(),
    };
    HttpResponse::Ok().json(SuccessResponse { success: true, data })
}

// --- Send SOL Endpoint ---
#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol(req: web::Json<SendSolRequest>) -> impl Responder {
    use solana_sdk::system_instruction::transfer;
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    // Validate lamports
    if req.lamports == 0 {
        return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "lamports must be non-zero and positive".to_string() });
    }
    // Validate addresses
    let from = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid from address (not base58)".to_string() }),
    };
    let to = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid to address (not base58)".to_string() }),
    };
    if from == to {
        return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "from and to address must not be the same".to_string() });
    }
    let instruction = transfer(&from, &to, req.lamports);
    let data = SendSolData {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|meta| meta.pubkey.to_string()).collect(),
        instruction_data: base64::encode(&instruction.data),
    };
    HttpResponse::Ok().json(SuccessResponse { success: true, data })
}

// --- Send Token Endpoint ---
#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccountMeta {
    pubkey: String,
    isSigner: bool,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
}

async fn send_token(req: web::Json<SendTokenRequest>) -> impl Responder {
    use spl_token::instruction::transfer;
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid destination address (not base58)".to_string() }),
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid mint address (not base58)".to_string() }),
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "Invalid owner address (not base58)".to_string() }),
    };
    if req.amount == 0 {
        return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: "amount must be non-zero and positive".to_string() });
    }
    // For demonstration, assume source token account is owner, destination is destination
    let instruction = match transfer(
        &spl_token::id(),
        &owner, // source token account (should be ATA in real use)
        &destination, // destination token account (should be ATA in real use)
        &owner, // owner
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return HttpResponse::BadRequest().json(ErrorResponse { success: false, error: format!("Failed to create transfer instruction: {}", e) }),
    };
    let accounts_serialized = instruction.accounts.iter().map(|meta| SendTokenAccountMeta {
        pubkey: meta.pubkey.to_string(),
        isSigner: meta.is_signer,
    }).collect();
    let data = SendTokenData {
        program_id: instruction.program_id.to_string(),
        accounts: accounts_serialized,
        instruction_data: base64::encode(&instruction.data),
    };
    HttpResponse::Ok().json(SuccessResponse { success: true, data })
}

// --- Error handler for 404 and others ---
async fn not_found() -> impl Responder {
    HttpResponse::NotFound().json(ErrorResponse {
        success: false,
        error: "Endpoint not found".to_string(),
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
            .default_service(web::route().to(not_found))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
