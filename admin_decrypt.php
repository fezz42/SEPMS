<?php

declare(strict_types=1);
session_start();

require_once 'includes/db.php';
require_once 'includes/crypto_helper.php';

if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Admin') {
    header('Location: index.php?error=unauthorized');
    exit;
}

$paper_id = isset($_GET['paper_id']) && ctype_digit((string) $_GET['paper_id'])
    ? (int) $_GET['paper_id']
    : 0;

if ($paper_id <= 0) {
    header('Location: dashboard.php?error=invalid_paper');
    exit;
}

$pdo = db();

$stmt = $pdo->prepare("
    SELECT 
        pf.stored_name,
        pf.original_name,
        pf.mime_type,
        pf.iv,
        pf.admin_key_cipher,
        pf.admin_key_iv,
        u.full_name AS lecturer_name,
        p.status
    FROM paper_files pf
    JOIN papers p ON pf.paper_id = p.id
    JOIN users u ON p.lecturer_id = u.id
    WHERE pf.paper_id = :paper_id
      AND p.status = 'Approved'
    LIMIT 1
");

$stmt->execute([
    ':paper_id' => $paper_id
]);

$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) {
    header('Location: dashboard.php?error=invalid_paper');
    exit;
}

if (empty($file['admin_key_cipher']) || empty($file['admin_key_iv'])) {
    die('Admin print key is missing. This paper may need to be resubmitted.');
}

try {
    $encryption_key = decryptAdminKey(
        (string) $file['admin_key_cipher'],
        (string) $file['admin_key_iv']
    );
} catch (Throwable $e) {
    die('Failed to read admin print key.');
}

$safe_full_name = str_replace(' ', '_', (string) $file['lecturer_name']);
$safe_full_name = preg_replace('/[\/\\\\:*?"<>|]/', '_', $safe_full_name);

$encrypted_file_path = dirname(__DIR__) . "/sepms_storage/papers/$safe_full_name/" . $file['stored_name'];

if (!file_exists($encrypted_file_path)) {
    die('File missing on server.');
}

$method = 'aes-256-cbc';
$iv_length = openssl_cipher_iv_length($method);

$encrypted_data = file_get_contents($encrypted_file_path);

if ($encrypted_data === false || strlen($encrypted_data) <= $iv_length) {
    die('Invalid encrypted file.');
}

$iv_file = substr($encrypted_data, 0, $iv_length);
$encrypted_content = substr($encrypted_data, $iv_length);

$iv_db = base64_decode((string) $file['iv'], true);

$iv = strlen($iv_file) === $iv_length ? $iv_file : $iv_db;

if ($iv === false || strlen($iv) !== $iv_length) {
    die('Invalid IV.');
}

$decrypted_data = openssl_decrypt(
    $encrypted_content,
    $method,
    $encryption_key,
    OPENSSL_RAW_DATA,
    $iv
);

if ($decrypted_data === false) {
    die('Decryption failed.');
}

header('Content-Type: ' . $file['mime_type']);
header('Content-Disposition: inline; filename="' . basename((string) $file['original_name']) . '"');
header('Content-Length: ' . strlen($decrypted_data));
header('Cache-Control: private, max-age=0, must-revalidate');
header('Pragma: public');

echo $decrypted_data;
exit;
