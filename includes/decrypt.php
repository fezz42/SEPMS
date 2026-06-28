<?php

declare(strict_types=1);
session_start();
require_once 'db.php';

// Ensure authorized
if (!isset($_SESSION['user']) || !in_array($_SESSION['user']['role'], ['Moderator', 'HOD'])) {
    header('Location: ../index.php?error=unauthorized');
    exit;
}

// Only allow POST because reviewer must enter the decryption key
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../dashboard.php?error=invalid_request');
    exit;
}

$paper_id = isset($_POST['paper_id']) && ctype_digit((string) $_POST['paper_id'])
    ? (int) $_POST['paper_id']
    : 0;

$encryption_key = trim((string) ($_POST['encryption_key'] ?? ''));

if ($paper_id <= 0 || $encryption_key === '') {
    header('Location: ../dashboard.php?error=invalid_request');
    exit;
}

// Fetch paper file info with role-based access control
$pdo = db();

$current_user_id = (int) $_SESSION['user']['id'];
$current_user_role = (string) $_SESSION['user']['role'];
$current_user_college = trim((string) ($_SESSION['user']['college'] ?? ''));

if ($current_user_role === 'Moderator') {
    $stmt = $pdo->prepare("
        SELECT 
            pf.stored_name, 
            pf.original_name, 
            pf.mime_type, 
            pf.iv, 
            u.full_name AS lecturer_name
        FROM paper_files pf
        JOIN papers p ON pf.paper_id = p.id
        JOIN users u ON p.lecturer_id = u.id
        WHERE pf.paper_id = :paper_id
          AND p.moderator_id = :moderator_id
        LIMIT 1
    ");

    $stmt->execute([
        ':paper_id' => $paper_id,
        ':moderator_id' => $current_user_id
    ]);
} elseif ($current_user_role === 'HOD') {
    $stmt = $pdo->prepare("
        SELECT 
            pf.stored_name, 
            pf.original_name, 
            pf.mime_type, 
            pf.iv, 
            u.full_name AS lecturer_name
        FROM paper_files pf
        JOIN papers p ON pf.paper_id = p.id
        JOIN users u ON p.lecturer_id = u.id
        WHERE pf.paper_id = :paper_id
          AND u.college = :college
        LIMIT 1
    ");

    $stmt->execute([
        ':paper_id' => $paper_id,
        ':college' => $current_user_college
    ]);
} else {
    header('Location: ../index.php?error=unauthorized');
    exit;
}

$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) {
    header('Location: ../dashboard.php?error=invalid_paper_access');
    exit;
}

// Path to encrypted file
$safe_full_name = str_replace(' ', '_', $file['lecturer_name']);
$safe_full_name = preg_replace('/[\/\\\\:*?"<>|]/', '_', $safe_full_name);
$encrypted_file_path = dirname(__DIR__, 2) . "/sepms_storage/papers/$safe_full_name/" . $file['stored_name'];

if (!file_exists($encrypted_file_path)) {
    header('Location: ../dashboard.php?error=file_missing');
    exit;
}

// Encryption settings
$key = $encryption_key;
$method = "aes-256-cbc";
$iv_length = openssl_cipher_iv_length($method);

// Read encrypted file
$encrypted_data = file_get_contents($encrypted_file_path);

// --- Extract IV and encrypted content ---
// Option 1: IV prepended in file
$iv_file = substr($encrypted_data, 0, $iv_length);
$encrypted_content = substr($encrypted_data, $iv_length);

// Option 2: IV stored in DB
$iv_db = base64_decode($file['iv']);

// Use IV from file if available, fallback to DB
$iv = $iv_file ?: $iv_db;

// Decrypt
$decrypted_data = openssl_decrypt($encrypted_content, $method, $key, OPENSSL_RAW_DATA, $iv);
if ($decrypted_data === false) {
    header('Location: ../dashboard.php?error=decryption_failed');
    exit;
}

// Output file to browser
header('Content-Description: File Transfer');
header('Content-Type: ' . $file['mime_type']);
header('Content-Disposition: inline; filename="' . basename((string) $file['original_name']) . '"');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . strlen($decrypted_data));

echo $decrypted_data;
exit;
