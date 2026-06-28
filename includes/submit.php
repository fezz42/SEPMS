<?php

declare(strict_types=1);
session_start();
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto_helper.php';

// --- Validate strong encryption key ---
function validateEncryptionKey(string $key): bool
{
    if (strlen($key) < 6) {
        return false;
    }

    if (preg_match('/\s/', $key)) {
        return false;
    }

    if (!preg_match('/[A-Z]/', $key)) {
        return false;
    }

    if (!preg_match('/[a-z]/', $key)) {
        return false;
    }

    if (!preg_match('/[0-9]/', $key)) {
        return false;
    }

    if (!preg_match('/[^A-Za-z0-9]/', $key)) {
        return false;
    }

    return true;
}

// --- Only allow POST requests ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../submit.php?error=invalid_request');
    exit;
}

// --- Ensure user is a lecturer ---
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Lecturer') {
    header('Location: ../index.php?error=unauthorized');
    exit;
}

// --- Safely get user info ---
$user = $_SESSION['user'];
$user_id = (int) $user['id'];
$full_name = $user['full_name'] ?? 'user';
$college = trim($user['college'] ?? '');

$paper_id = isset($_POST['paper_id']) && ctype_digit((string) $_POST['paper_id'])
    ? (int) $_POST['paper_id']
    : null;

$is_resubmit = $paper_id !== null;

// --- Fetch POST data ---
$paper_name = trim((string) ($_POST['paper_name'] ?? ''));
$paper_description = trim((string) ($_POST['paper_description'] ?? ''));
$subject_id = isset($_POST['subject_id']) ? (int) $_POST['subject_id'] : 0;
$moderator_id = 0;
$encryption_key = trim((string) ($_POST['encryption_key'] ?? ''));

// Used for redirect back to submit page
$redirect_paper_param = $paper_id !== null ? '&paper_id=' . $paper_id : '';

// --- Validate required fields ---
if ($paper_name === '' || $paper_description === '' || $encryption_key === '') {
    header('Location: ../submit.php?error=invalid_request' . $redirect_paper_param);
    exit;
}

if (!$is_resubmit && $subject_id === 0) {
    header('Location: ../submit.php?error=invalid_subject');
    exit;
}

// --- Validate encryption key strength ---
if (!validateEncryptionKey($encryption_key)) {
    header('Location: ../submit.php?error=weak_key' . $redirect_paper_param);
    exit;
}

try {
    $pdo = db();

    // --- If resubmitting, verify paper belongs to current lecturer and force original moderator ---
    if ($is_resubmit) {
        $stmt_existing = $pdo->prepare("
            SELECT id, moderator_id, subject_id, status
            FROM papers
            WHERE id = :paper_id
            AND lecturer_id = :lecturer_id
            LIMIT 1
        ");
        $stmt_existing->execute([
            ':paper_id' => $paper_id,
            ':lecturer_id' => $user_id
        ]);

        $existing_paper = $stmt_existing->fetch(PDO::FETCH_ASSOC);

        if (!$existing_paper) {
            header('Location: ../dashboard.php?error=invalid_paper');
            exit;
        }

        // Only rejected papers can be resubmitted
        if (!in_array($existing_paper['status'], ['Rejected by Moderator', 'Rejected by HOD'], true)) {
            header('Location: ../dashboard.php?error=resubmit_not_allowed');
            exit;
        }

        // Prevent lecturer from changing moderator using inspect element
        $moderator_id = (int) $existing_paper['moderator_id'];
        $subject_id = (int) $existing_paper['subject_id'];
    }

    // --- For new submission, validate subject and auto-get assigned moderator ---
    if (!$is_resubmit) {
        if ($subject_id === 0) {
            header('Location: ../submit.php?error=invalid_subject');
            exit;
        }

        if ($college !== '') {
            $stmt_subject = $pdo->prepare("
            SELECT 
                s.id,
                s.moderator_id
            FROM subjects s
            JOIN users u ON s.moderator_id = u.id
            WHERE s.id = :subject_id
              AND s.status = 'active'
              AND s.college = :college
              AND u.role = 'Moderator'
              AND u.registration = 'approved'
              AND u.status = 'active'
            LIMIT 1
        ");

            $stmt_subject->execute([
                ':subject_id' => $subject_id,
                ':college' => $college
            ]);
        } else {
            $stmt_subject = $pdo->prepare("
            SELECT 
                s.id,
                s.moderator_id
            FROM subjects s
            JOIN users u ON s.moderator_id = u.id
            WHERE s.id = :subject_id
              AND s.status = 'active'
              AND u.role = 'Moderator'
              AND u.registration = 'approved'
              AND u.status = 'active'
            LIMIT 1
        ");

            $stmt_subject->execute([
                ':subject_id' => $subject_id
            ]);
        }

        $subject = $stmt_subject->fetch(PDO::FETCH_ASSOC);

        if (!$subject) {
            header('Location: ../submit.php?error=invalid_subject');
            exit;
        }

        $moderator_id = (int) $subject['moderator_id'];
    }
} catch (PDOException $e) {
    error_log('Validation database error: ' . $e->getMessage());
    header('Location: ../submit.php?error=db_error' . $redirect_paper_param);
    exit;
}

// --- Validate uploaded file ---
if (!isset($_FILES['paper_file']) || $_FILES['paper_file']['error'] !== UPLOAD_ERR_OK) {
    header('Location: ../submit.php?error=no_file' . $redirect_paper_param);
    exit;
}

$file = $_FILES['paper_file'];
$file_tmp = (string) $file['tmp_name'];
$file_ext = strtolower(pathinfo((string) $file['name'], PATHINFO_EXTENSION));

$max_file_size = 20 * 1024 * 1024; // 20MB

$allowed_mimes = [
    'pdf' => [
        'application/pdf'
    ],
    'docx' => [
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/zip'
    ]
];

// Make sure file was uploaded through HTTP POST
if (!is_uploaded_file($file_tmp)) {
    header('Location: ../submit.php?error=invalid_file' . $redirect_paper_param);
    exit;
}

// Check file size
if ((int) $file['size'] <= 0 || (int) $file['size'] > $max_file_size) {
    header('Location: ../submit.php?error=invalid_file_size' . $redirect_paper_param);
    exit;
}

// Check file extension
if (!array_key_exists($file_ext, $allowed_mimes)) {
    header('Location: ../submit.php?error=invalid_file' . $redirect_paper_param);
    exit;
}

// Check real MIME type
$finfo = new finfo(FILEINFO_MIME_TYPE);
$detected_mime = $finfo->file($file_tmp);

if ($detected_mime === false || !in_array($detected_mime, $allowed_mimes[$file_ext], true)) {
    header('Location: ../submit.php?error=invalid_file_type' . $redirect_paper_param);
    exit;
}

// --- Prepare safe file paths ---
$safe_full_name = preg_replace('/[\/\\\\:*?"<>|]/', '_', str_replace(' ', '_', $full_name));

$base_upload_path = dirname(__DIR__, 2) . '/sepms_storage/papers';

if (!is_dir($base_upload_path)) {
    mkdir($base_upload_path, 0750, true);
}

$upload_dir = $base_upload_path . DIRECTORY_SEPARATOR . $safe_full_name . DIRECTORY_SEPARATOR;

if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0750, true);
}

$stored_name = bin2hex(random_bytes(16)) . '.enc';
$final_file = $upload_dir . $stored_name;

// --- Encrypt file using lecturer-provided encryption key ---
$method = 'aes-256-cbc';
$iv_length = openssl_cipher_iv_length($method);

if ($iv_length === false) {
    header('Location: ../submit.php?error=encrypt_failed' . $redirect_paper_param);
    exit;
}

$iv = openssl_random_pseudo_bytes($iv_length);
$file_data = file_get_contents($file_tmp);

if ($file_data === false) {
    header('Location: ../submit.php?error=upload_failed' . $redirect_paper_param);
    exit;
}

$encrypted_data = openssl_encrypt($file_data, $method, $encryption_key, OPENSSL_RAW_DATA, $iv);

if ($encrypted_data === false) {
    header('Location: ../submit.php?error=encrypt_failed' . $redirect_paper_param);
    exit;
}

$final_data = $iv . $encrypted_data;

if (file_put_contents($final_file, $final_data, LOCK_EX) === false) {
    header('Location: ../submit.php?error=upload_failed' . $redirect_paper_param);
    exit;
}

chmod($final_file, 0640);

// --- Database operations ---
try {
    $pdo = db();
    $pdo->beginTransaction();

    if ($paper_id === null) {
        // --- New paper submission ---
        $stmt = $pdo->prepare("
            INSERT INTO papers (
                lecturer_id,
                subject_id,
                paper_name,
                paper_description,
                status,
                submission_date,
                moderator_id
            )
            VALUES (
                :lecturer_id,
                :subject_id,
                :paper_name,
                :paper_description,
                'Pending Moderator Review',
                NOW(),
                :moderator_id
            )
        ");

        $stmt->execute([
            ':lecturer_id' => $user_id,
            ':subject_id' => $subject_id,
            ':paper_name' => $paper_name,
            ':paper_description' => $paper_description,
            ':moderator_id' => $moderator_id
        ]);

        $paper_id = (int) $pdo->lastInsertId();
        $new_status = 'Pending Moderator Review';
    } else {
        // --- Get current paper status before updating ---
        $stmt_status = $pdo->prepare("
            SELECT status
            FROM papers
            WHERE id = :paper_id
            AND lecturer_id = :lecturer_id
            LIMIT 1
        ");
        $stmt_status->execute([
            ':paper_id' => $paper_id,
            ':lecturer_id' => $user_id
        ]);

        $current_status = $stmt_status->fetchColumn();

        if (!$current_status) {
            $pdo->rollBack();
            header('Location: ../dashboard.php?error=invalid_paper');
            exit;
        }

        // --- Decide next status after resubmission ---
        $new_status = match ($current_status) {
            'Rejected by Moderator' => 'Pending Moderator Review',
            'Rejected by HOD' => 'Pending HOD Review',
            default => null,
        };

        if ($new_status === null) {
            $pdo->rollBack();
            header('Location: ../dashboard.php?error=resubmit_not_allowed');
            exit;
        }

        // --- Update existing paper ---
        $stmt = $pdo->prepare("
            UPDATE papers
            SET paper_name = :paper_name,
                paper_description = :paper_description,
                subject_id = :subject_id,
                moderator_id = :moderator_id,
                status = :status,
                submission_date = NOW()
            WHERE id = :paper_id
            AND lecturer_id = :lecturer_id
        ");

        $stmt->execute([
            ':paper_name' => $paper_name,
            ':paper_description' => $paper_description,
            ':subject_id' => $subject_id,
            ':moderator_id' => $moderator_id,
            ':status' => $new_status,
            ':paper_id' => $paper_id,
            ':lecturer_id' => $user_id
        ]);
    }

    // --- Insert or update paper_files table ---
    $stmt_check = $pdo->prepare("
    SELECT id
    FROM paper_files
    WHERE paper_id = :paper_id
    ORDER BY id DESC
    LIMIT 1
");
    $stmt_check->execute([
        ':paper_id' => $paper_id
    ]);

    $existing_file = $stmt_check->fetch(PDO::FETCH_ASSOC);

    // Encrypt lecturer-provided key for Admin printing
    $adminKey = encryptAdminKey($encryption_key);

    $file_params = [
        ':stored_name' => $stored_name,
        ':original_name' => $paper_name . '.' . $file_ext,
        ':mime_type' => $detected_mime,
        ':file_size' => $file['size'],
        ':iv' => base64_encode($iv),
        ':admin_key_cipher' => $adminKey['cipher'],
        ':admin_key_iv' => $adminKey['iv']
    ];

    if ($existing_file) {
        $file_params[':id'] = $existing_file['id'];

        $stmt_file = $pdo->prepare("
        UPDATE paper_files
        SET stored_name = :stored_name,
            original_name = :original_name,
            mime_type = :mime_type,
            file_size = :file_size,
            iv = :iv,
            admin_key_cipher = :admin_key_cipher,
            admin_key_iv = :admin_key_iv
        WHERE id = :id
    ");

        $stmt_file->execute($file_params);
    } else {
        $file_params[':paper_id'] = $paper_id;

        $stmt_file = $pdo->prepare("
        INSERT INTO paper_files (
            paper_id,
            stored_name,
            original_name,
            mime_type,
            file_size,
            iv,
            admin_key_cipher,
            admin_key_iv
        )
        VALUES (
            :paper_id,
            :stored_name,
            :original_name,
            :mime_type,
            :file_size,
            :iv,
            :admin_key_cipher,
            :admin_key_iv
        )
    ");

        $stmt_file->execute($file_params);
    }

    // --- Logging into paper_actions ---
    $action_name = $is_resubmit ? 'Resubmitted' : 'Submitted';

    $stmt_action = $pdo->prepare("
        INSERT INTO paper_actions (
            paper_id,
            actor_id,
            actor_role,
            action,
            feedback
        )
        VALUES (
            :paper_id,
            :actor_id,
            'Lecturer',
            :action,
            NULL
        )
    ");

    $stmt_action->execute([
        ':paper_id' => $paper_id,
        ':actor_id' => $user_id,
        ':action' => $action_name
    ]);

    // --- Logging into action_logs ---
    $log_description = $is_resubmit
        ? 'Paper resubmitted successfully. Status updated to ' . $new_status . '.'
        : 'Paper submitted successfully. Status updated to ' . $new_status . '.';

    $stmt_log = $pdo->prepare("
    INSERT INTO action_logs (
        user_id,
        paper_id,
        action_type,
        description
    )
    VALUES (
        :user_id,
        :paper_id,
        :action_type,
        :description
    )
");

    $stmt_log->execute([
        ':user_id' => $user_id,
        ':paper_id' => $paper_id,
        ':action_type' => $action_name,
        ':description' => $log_description
    ]);

    $pdo->commit();

    header('Location: ../submit.php?encrypting=1&paper_id=' . $paper_id);
    exit;
} catch (PDOException $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('Submit process database error: ' . $e->getMessage());

    header('Location: ../submit.php?error=db_error' . ($paper_id ? '&paper_id=' . $paper_id : ''));
    exit;
}
