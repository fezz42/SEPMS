<?php

declare(strict_types=1);
session_start();
require_once 'includes/db.php';

// --- Ensure user is a lecturer ---
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Lecturer') {
    header('Location: index.php?error=unauthorized');
    exit;
}

// --- Safely get user info ---
$user = $_SESSION['user'];
$user_id = (int) $user['id'];
$full_name = $user['full_name'] ?? 'user';
$college = trim($_SESSION['user']['college'] ?? '');

$paper_id = isset($_GET['paper_id']) && ctype_digit((string) $_GET['paper_id'])
    ? (int) $_GET['paper_id']
    : null;

$is_resubmit = $paper_id !== null;

// --- Message Handling ---
$msg = '';
$msg_type = '';

if (isset($_GET['success']) && $_GET['success'] === '1') {
    $msg = 'Encryption Successful!';
    $msg_type = 'success';
} elseif (isset($_GET['encrypting']) && $_GET['encrypting'] === '1') {
    $msg = 'Encrypting your paper...<br>Securing your examination paper with encryption';
    $msg_type = 'encrypt';
} elseif (isset($_GET['error'])) {
    $errors = [
        'invalid_request' => 'Please complete all required fields.',
        'invalid_file' => 'Invalid file format. Only PDF or DOCX are allowed.',
        'invalid_file_size' => 'File size is invalid. Maximum allowed size is 20MB.',
        'invalid_file_type' => 'Invalid file type detected. Only PDF or DOCX are allowed.',
        'no_file' => 'No file was uploaded. Please select a file to upload.',
        'db_error' => 'An error occurred while saving your paper. Please try again later.',
        'encrypt_failed' => 'Error encrypting the file. Please try again.',
        'upload_failed' => 'Error uploading the file. Please try again.',
        'invalid_paper' => 'Invalid paper selected.',
        'invalid_moderator' => 'Invalid moderator selected.',
        'weak_key' => 'Encryption key must be at least 6 characters and include uppercase, lowercase, number, special character, and no spaces.',
        'invalid_subject' => 'Invalid subject selected or no moderator has been assigned to this subject.',
        'no_subjects' => 'No subjects are available for your college. Please contact Admin.'
    ];

    $msg = $errors[$_GET['error']] ?? 'Something went wrong. Please try again.';
    $msg_type = 'error';
}

// --- Prefill existing paper data if resubmitting ---
$paper_data = null;

if ($paper_id !== null) {
    $stmt = db()->prepare("
        SELECT paper_name, paper_description, moderator_id, subject_id
        FROM papers
        WHERE id = :paper_id
        AND lecturer_id = :lecturer_id
        LIMIT 1
    ");

    $stmt->execute([
        ':paper_id' => $paper_id,
        ':lecturer_id' => $user_id
    ]);

    $paper_data = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$paper_data) {
        header('Location: dashboard.php?error=invalid_paper');
        exit;
    }
}

// --- Fetch subjects with assigned moderators ---
$subjects = [];

try {
    $pdo = db();

    if ($college !== '') {
        $stmt = $pdo->prepare("
            SELECT 
                s.id,
                s.subject_code,
                s.subject_name,
                s.college,
                s.moderator_id,
                u.full_name AS moderator_name
            FROM subjects s
            JOIN users u ON s.moderator_id = u.id
            WHERE s.status = 'active'
              AND s.college = :college
              AND u.role = 'Moderator'
              AND u.registration = 'approved'
              AND u.status = 'active'
            ORDER BY s.subject_code
        ");

        $stmt->execute([':college' => $college]);
    } else {
        $stmt = $pdo->query("
            SELECT 
                s.id,
                s.subject_code,
                s.subject_name,
                s.college,
                s.moderator_id,
                u.full_name AS moderator_name
            FROM subjects s
            JOIN users u ON s.moderator_id = u.id
            WHERE s.status = 'active'
              AND u.role = 'Moderator'
              AND u.registration = 'approved'
              AND u.status = 'active'
            ORDER BY s.college, s.subject_code
        ");
    }

    $subjects = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('Fetch subjects error: ' . $e->getMessage());
    $subjects = [];
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $is_resubmit ? 'Resubmit Paper' : 'Submit New Exam Paper'; ?> - SEPMS</title>

    <link rel="stylesheet" href="assets/css/submitL.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">

    <style>
        .key-hint,
        .subject-hint {
            display: block;
            margin-top: 6px;
            margin-bottom: 12px;
            font-size: 12px;
            color: #666;
            line-height: 1.4;
        }

        .readonly-box {
            background-color: #f5f5f5;
            cursor: not-allowed;
        }
    </style>
</head>

<body>

    <div class="dashboard-header">
        <div class="container">
            <div class="header-left">
                <div class="logout">
                    <a href="dashboard.php" class="back-link">
                        <i class="fas fa-arrow-left logout-icon"></i> Back to Dashboard
                    </a>
                </div>
            </div>
        </div>
    </div>

    <div class="login-container">
        <div class="login-card">
            <div class="login-header">
                <h2><?= $is_resubmit ? 'Resubmit Paper' : 'Submit New Paper'; ?></h2>
                <h4><?= $is_resubmit ? 'Reupload your examination paper for review' : 'Upload your examination paper for review'; ?></h4>
            </div>

            <?php if ($msg !== ''): ?>
                <div class="msg <?= htmlspecialchars($msg_type, ENT_QUOTES, 'UTF-8'); ?>">
                    <i class="fa-solid <?= $msg_type === 'success' ? 'fa-circle-check' : 'fa-lock'; ?>"
                        style="color: <?= $msg_type === 'success' ? '#4CAF50' : ($msg_type === 'encrypt' ? '#1e70d3' : '#f44336'); ?>; padding-right: 10px;"></i>
                    <?= $msg; ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="includes/submit.php" enctype="multipart/form-data" id="submit-form">

                <?php if ($paper_id !== null): ?>
                    <input type="hidden" name="paper_id" value="<?= htmlspecialchars((string) $paper_id, ENT_QUOTES, 'UTF-8'); ?>">
                <?php endif; ?>

                <!-- Hidden paper name: automatically filled from selected subject -->
                <input
                    type="hidden"
                    name="paper_name"
                    id="paper_name"
                    value="<?= htmlspecialchars($paper_data['paper_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">

                <?php if (!empty($subjects)): ?>
                    <h5>Select Subject *</h5>

                    <select
                        name="subject_id"
                        id="subject_id"
                        <?= $is_resubmit ? 'disabled' : ''; ?>
                        required>

                        <option value="">Select Subject</option>

                        <?php foreach ($subjects as $subject): ?>
                            <?php
                            $subject_display = $subject['subject_code'] . ' - ' . $subject['subject_name'];
                            $is_selected = isset($paper_data['subject_id']) && (int) $paper_data['subject_id'] === (int) $subject['id'];
                            ?>

                            <option
                                value="<?= htmlspecialchars((string) $subject['id'], ENT_QUOTES, 'UTF-8'); ?>"
                                data-paper-name="<?= htmlspecialchars($subject_display, ENT_QUOTES, 'UTF-8'); ?>"
                                data-moderator="<?= htmlspecialchars((string) $subject['moderator_name'], ENT_QUOTES, 'UTF-8'); ?>"
                                <?= $is_selected ? 'selected' : ''; ?>>

                                <?= htmlspecialchars($subject_display, ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>

                    <small class="subject-hint">
                        Select the subject for this examination paper. The assigned moderator will be shown automatically.
                    </small>

                    <?php if ($is_resubmit && isset($paper_data['subject_id'])): ?>
                        <input
                            type="hidden"
                            name="subject_id"
                            value="<?= htmlspecialchars((string) $paper_data['subject_id'], ENT_QUOTES, 'UTF-8'); ?>">
                    <?php endif; ?>

                    <h5 style="margin-top: 15px;">Assigned Moderator</h5>
                    <input
                        type="text"
                        id="assigned_moderator"
                        value=""
                        placeholder="Moderator will appear after selecting subject"
                        class="readonly-box"
                        readonly>

                <?php else: ?>
                    <p style="color:red;">
                        No subjects are available for your college. Please contact Admin.
                    </p>
                <?php endif; ?>

                <h5>Paper Description *</h5>
                <textarea
                    id="paper_description"
                    name="paper_description"
                    placeholder="Provide a brief description..."
                    required><?= htmlspecialchars($paper_data['paper_description'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>

                <h5>Upload Paper File (PDF/DOCX) *</h5>
                <input type="file" name="paper_file" accept=".pdf,.docx" required>

                <h5 style="margin-top: 25px;">Enter Encryption Key *</h5>
                <input
                    type="password"
                    name="encryption_key"
                    id="encryption_key"
                    placeholder="Minimum 6 characters with uppercase, lowercase, number & symbol"
                    pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d])\S{6,}$"
                    title="Encryption key must be at least 6 characters and include uppercase, lowercase, number, special character, and no spaces."
                    autocomplete="off"
                    required>

                <small class="key-hint">
                    Key must contain at least 6 characters, uppercase letter, lowercase letter, number, special character, and no spaces.
                </small>

                <div class="login-options">
                    <button
                        type="submit"
                        class="btn-submit"
                        <?= empty($subjects) ? 'disabled' : ''; ?>>

                        <i class="fa-solid fa-arrow-up-from-bracket" style="color: #ffffff; padding-right: 10px;"></i>
                        <?= $is_resubmit ? 'Resubmit Paper' : 'Submit Paper'; ?>
                    </button>

                    <button
                        type="button"
                        class="btn-cancel"
                        onclick="window.location.href='dashboard.php'">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>

    <?php if ($msg_type === 'encrypt'): ?>
        <script>
            setTimeout(() => {
                const msgDiv = document.querySelector('.msg');

                msgDiv.classList.remove('encrypt');
                msgDiv.classList.add('success');
                msgDiv.innerHTML = '<i class="fa-solid fa-circle-check" style="color: #4CAF50; padding-right: 10px;"></i> Encryption Successful!';

                setTimeout(() => {
                    window.location.href = 'dashboard.php';
                }, 1500);
            }, 1500);
        </script>
    <?php endif; ?>

    <script>
        const subjectSelect = document.getElementById('subject_id');
        const assignedModerator = document.getElementById('assigned_moderator');
        const paperNameInput = document.getElementById('paper_name');
        const submitForm = document.getElementById('submit-form');

        function updateSubjectDetails() {
            if (!subjectSelect || !assignedModerator || !paperNameInput) {
                return;
            }

            const selectedOption = subjectSelect.options[subjectSelect.selectedIndex];

            if (selectedOption && selectedOption.value !== '') {
                assignedModerator.value = selectedOption.dataset.moderator || '';
                paperNameInput.value = selectedOption.dataset.paperName || '';
            } else {
                assignedModerator.value = '';
                paperNameInput.value = '';
            }
        }

        if (subjectSelect) {
            subjectSelect.addEventListener('change', updateSubjectDetails);
            document.addEventListener('DOMContentLoaded', updateSubjectDetails);
        }

        submitForm.addEventListener('submit', function(event) {
            updateSubjectDetails();

            if (!paperNameInput.value.trim()) {
                event.preventDefault();
                alert('Please select a subject before submitting.');
            }
        });
    </script>

</body>

</html>