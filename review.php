<?php

declare(strict_types=1);
session_start();

require_once 'includes/db.php';

if (!isset($_SESSION['user']) || !in_array($_SESSION['user']['role'], ['Moderator', 'HOD'], true)) {
    header('Location: index.php?error=unauthorized');
    exit;
}

if (empty($_SESSION['csrf_review_action'])) {
    $_SESSION['csrf_review_action'] = bin2hex(random_bytes(32));
}

$paper_id = isset($_GET['paper_id']) && ctype_digit((string) $_GET['paper_id'])
    ? (int) $_GET['paper_id']
    : null;

if ($paper_id === null) {
    header('Location: dashboard.php?error=invalid_request');
    exit;
}

$user_id = (int) $_SESSION['user']['id'];
$user_role = (string) $_SESSION['user']['role'];
$user_college = trim((string) ($_SESSION['user']['college'] ?? ''));

function json_response(array $data, int $status_code = 200): void
{
    http_response_code($status_code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function safe_storage_folder(string $lecturer_name): string
{
    $safe_full_name = str_replace(' ', '_', $lecturer_name);
    return (string) preg_replace('/[\/\\\\:*?"<>|]/', '_', $safe_full_name);
}

function decrypt_review_file(array $file, string $lecturer_name, string $encryption_key): array
{
    if (empty($file['stored_name'])) {
        throw new RuntimeException('file_not_found');
    }

    $safe_full_name = safe_storage_folder($lecturer_name);
    $encrypted_file_path = dirname(__DIR__) . "/sepms_storage/papers/$safe_full_name/" . $file['stored_name'];

    if (!is_file($encrypted_file_path)) {
        throw new RuntimeException('file_not_found');
    }

    $method = 'aes-256-cbc';
    $iv_length = openssl_cipher_iv_length($method);

    if ($iv_length === false) {
        throw new RuntimeException('decrypt_failed');
    }

    $encrypted_data = file_get_contents($encrypted_file_path);

    if ($encrypted_data === false || strlen($encrypted_data) <= $iv_length) {
        throw new RuntimeException('decrypt_failed');
    }

    $iv_from_file = substr($encrypted_data, 0, $iv_length);
    $encrypted_content = substr($encrypted_data, $iv_length);

    $iv_from_db = base64_decode((string) ($file['iv'] ?? ''), true);
    $iv = strlen($iv_from_file) === $iv_length ? $iv_from_file : ($iv_from_db ?: '');

    if (strlen($iv) !== $iv_length) {
        throw new RuntimeException('decrypt_failed');
    }

    $decrypted_data = openssl_decrypt(
        $encrypted_content,
        $method,
        $encryption_key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($decrypted_data === false) {
        throw new RuntimeException('decrypt_failed');
    }

    return [
        'data' => $decrypted_data,
        'mime_type' => (string) ($file['mime_type'] ?? 'application/octet-stream'),
        'original_name' => (string) ($file['original_name'] ?? 'paper')
    ];
}

$pdo = db();

// Fetch paper details with role-based access control
if ($user_role === 'Moderator') {
    $stmt = $pdo->prepare("
        SELECT 
            p.*, 
            u.full_name AS lecturer_name
        FROM papers p
        JOIN users u ON p.lecturer_id = u.id
        WHERE p.id = :paper_id
          AND p.status = 'Pending Moderator Review'
          AND p.moderator_id = :user_id
        LIMIT 1
    ");

    $stmt->execute([
        ':paper_id' => $paper_id,
        ':user_id' => $user_id
    ]);
} else {
    $stmt = $pdo->prepare("
        SELECT 
            p.*, 
            u.full_name AS lecturer_name
        FROM papers p
        JOIN users u ON p.lecturer_id = u.id
        WHERE p.id = :paper_id
          AND p.status = 'Pending HOD Review'
          AND u.college = :college
        LIMIT 1
    ");

    $stmt->execute([
        ':paper_id' => $paper_id,
        ':college' => $user_college
    ]);
}

$paper = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$paper) {
    header('Location: dashboard.php?error=invalid_paper');
    exit;
}

// Latest file
$stmt_file = $pdo->prepare("
    SELECT pf.stored_name, pf.original_name, pf.mime_type, pf.iv
    FROM paper_files pf
    WHERE pf.paper_id = :paper_id
    ORDER BY pf.id DESC
    LIMIT 1
");
$stmt_file->execute([':paper_id' => $paper_id]);
$latest_file = $stmt_file->fetch(PDO::FETCH_ASSOC);

if (!$latest_file) {
    $latest_file = [
        'stored_name' => '',
        'original_name' => 'No file uploaded',
        'mime_type' => 'application/octet-stream',
        'iv' => ''
    ];
}

// --- Force key re-entry after page refresh ---
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    unset($_SESSION['review_verified_papers'][$paper_id]);
}

// --- AJAX: verify key or view paper in popup ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_action'])) {
    if (
        empty($_POST['csrf_token']) ||
        empty($_SESSION['csrf_review_action']) ||
        !hash_equals($_SESSION['csrf_review_action'], (string) $_POST['csrf_token'])
    ) {
        json_response(['success' => false, 'message' => 'Invalid request token. Please refresh the page and try again.'], 403);
    }

    $ajax_action = (string) $_POST['ajax_action'];

    if ($ajax_action === 'verify_key') {
        $encryption_key = trim((string) ($_POST['encryption_key'] ?? ''));

        if ($encryption_key === '') {
            json_response(['success' => false, 'message' => 'Please enter the decryption key.'], 400);
        }

        try {
            decrypt_review_file($latest_file, (string) $paper['lecturer_name'], $encryption_key);

            $verification_token = bin2hex(random_bytes(32));

            if (!isset($_SESSION['review_verified_papers'])) {
                $_SESSION['review_verified_papers'] = [];
            }

            $_SESSION['review_verified_papers'][$paper_id] = [
                'token' => $verification_token,
                'key' => $encryption_key,
                'verified_at' => time(),
                'viewed' => false
            ];

            json_response([
                'success' => true,
                'message' => 'Decryption key is correct. You can now view the paper.',
                'token' => $verification_token,
                'filename' => (string) $latest_file['original_name'],
                'mime_type' => (string) $latest_file['mime_type']
            ]);
        } catch (RuntimeException $e) {
            json_response(['success' => false, 'message' => 'Incorrect decryption key or file cannot be decrypted.'], 400);
        }
    }

    if ($ajax_action === 'view_file') {
        $verification_token = (string) ($_POST['verification_token'] ?? '');
        $verified_info = $_SESSION['review_verified_papers'][$paper_id] ?? null;

        if (
            !is_array($verified_info) ||
            empty($verified_info['token']) ||
            !hash_equals((string) $verified_info['token'], $verification_token) ||
            empty($verified_info['key']) ||
            ((int) ($verified_info['verified_at'] ?? 0) + 1800) < time()
        ) {
            http_response_code(403);
            header('Content-Type: text/plain');
            echo 'Verification expired. Please enter the decryption key again.';
            exit;
        }

        try {
            $decrypted_file = decrypt_review_file($latest_file, (string) $paper['lecturer_name'], (string) $verified_info['key']);

            $_SESSION['review_verified_papers'][$paper_id]['viewed'] = true;

            header('Content-Type: ' . $decrypted_file['mime_type']);
            header('Content-Disposition: inline; filename="' . basename($decrypted_file['original_name']) . '"');
            header('Cache-Control: private, max-age=0, must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . strlen($decrypted_file['data']));

            echo $decrypted_file['data'];
            exit;
        } catch (RuntimeException $e) {
            http_response_code(400);
            header('Content-Type: text/plain');
            echo 'Unable to decrypt the file. Please check the key and try again.';
            exit;
        }
    }

    json_response(['success' => false, 'message' => 'Invalid action.'], 400);
}

// --- Message Handling ---
$msg = '';
$msg_type = '';

if (isset($_GET['success']) && $_GET['success'] === '1') {
    $msg = 'Review submitted successfully!';
    $msg_type = 'success';
} elseif (isset($_GET['error'])) {
    $errors = [
        'invalid_request' => 'Invalid request. Please try again.',
        'invalid_paper' => 'Invalid paper selected or you are not allowed to review this paper.',
        'invalid_csrf' => 'Invalid request token. Please refresh the page and try again.',
        'missing_decision' => 'Please select Approve or Reject before submitting.',
        'feedback_required' => 'Feedback is required when rejecting the paper.',
        'db_error' => 'A database error occurred while submitting your review. Please try again later.',
        'unauthorized' => 'You are not authorized to access this page.',
        'decrypt_failed' => 'Unable to decrypt the paper. Please check the decryption key.',
        'missing_key' => 'Please enter the decryption key.',
        'file_not_found' => 'The uploaded paper file could not be found.',
        'paper_not_viewed' => 'Please enter the correct key and view the paper before submitting a decision.',
        'verification_expired' => 'Your decryption verification has expired. Please enter the key again.'
    ];

    $msg = $errors[$_GET['error']] ?? 'Something went wrong. Please try again.';
    $msg_type = 'error';
}

$verified_info = $_SESSION['review_verified_papers'][$paper_id] ?? null;
$review_unlocked = is_array($verified_info)
    && !empty($verified_info['token'])
    && !empty($verified_info['viewed'])
    && ((int) ($verified_info['verified_at'] ?? 0) + 1800) >= time();

$existing_verification_token = $review_unlocked ? (string) $verified_info['token'] : '';

// Handle POST review decision
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (
        empty($_POST['csrf_token']) ||
        empty($_SESSION['csrf_review_action']) ||
        !hash_equals($_SESSION['csrf_review_action'], (string) $_POST['csrf_token'])
    ) {
        header('Location: review.php?paper_id=' . $paper_id . '&error=invalid_csrf');
        exit;
    }

    $submitted_token = (string) ($_POST['verification_token'] ?? '');
    $verified_info = $_SESSION['review_verified_papers'][$paper_id] ?? null;

    if (
        !is_array($verified_info) ||
        empty($verified_info['token']) ||
        !hash_equals((string) $verified_info['token'], $submitted_token) ||
        empty($verified_info['viewed'])
    ) {
        header('Location: review.php?paper_id=' . $paper_id . '&error=paper_not_viewed');
        exit;
    }

    if (((int) ($verified_info['verified_at'] ?? 0) + 1800) < time()) {
        unset($_SESSION['review_verified_papers'][$paper_id]);
        header('Location: review.php?paper_id=' . $paper_id . '&error=verification_expired');
        exit;
    }

    $decision = $_POST['decision'] ?? '';
    $feedback = trim((string) ($_POST['feedback'] ?? ''));

    if (!$decision) {
        header('Location: review.php?paper_id=' . $paper_id . '&error=missing_decision');
        exit;
    }

    if (!in_array($decision, ['Approve', 'Reject'], true)) {
        header('Location: review.php?paper_id=' . $paper_id . '&error=missing_decision');
        exit;
    }

    if ($decision === 'Reject' && $feedback === '') {
        header('Location: review.php?paper_id=' . $paper_id . '&error=feedback_required');
        exit;
    }

    $action_db = $decision === 'Approve' ? 'Approved' : 'Rejected';
    $new_status = '';

    try {
        $pdo->beginTransaction();

        // Log paper action
        $stmt_action = $pdo->prepare("
            INSERT INTO paper_actions (paper_id, actor_id, action, feedback, actor_role)
            VALUES (:paper_id, :actor_id, :action, :feedback, :actor_role)
        ");
        $stmt_action->execute([
            ':paper_id' => $paper_id,
            ':actor_id' => $user_id,
            ':action' => $action_db,
            ':feedback' => $feedback,
            ':actor_role' => $user_role
        ]);

        // Update paper status
        if ($decision === 'Approve') {
            if ($user_role === 'Moderator') {
                $new_status = 'Pending HOD Review';

                $stmt_update = $pdo->prepare("
                    UPDATE papers
                    SET status = :status
                    WHERE id = :paper_id
                      AND moderator_id = :moderator_id
                ");

                $stmt_update->execute([
                    ':status' => $new_status,
                    ':paper_id' => $paper_id,
                    ':moderator_id' => $user_id
                ]);
            } elseif ($user_role === 'HOD') {
                $new_status = 'Approved';

                $stmt_update = $pdo->prepare("
                    UPDATE papers
                    SET 
                        status = :status,
                        hod_id = :hod_id
                    WHERE id = :paper_id
                ");

                $stmt_update->execute([
                    ':status' => $new_status,
                    ':paper_id' => $paper_id,
                    ':hod_id' => $user_id
                ]);
            }
        } elseif ($decision === 'Reject') {
            if ($user_role === 'Moderator') {
                $new_status = 'Rejected by Moderator';

                $stmt_update = $pdo->prepare("
                    UPDATE papers
                    SET status = :status
                    WHERE id = :paper_id
                      AND moderator_id = :moderator_id
                ");

                $stmt_update->execute([
                    ':status' => $new_status,
                    ':paper_id' => $paper_id,
                    ':moderator_id' => $user_id
                ]);
            } elseif ($user_role === 'HOD') {
                $new_status = 'Rejected by HOD';

                $stmt_update = $pdo->prepare("
                    UPDATE papers
                    SET 
                        status = :status,
                        hod_id = :hod_id
                    WHERE id = :paper_id
                ");

                $stmt_update->execute([
                    ':status' => $new_status,
                    ':paper_id' => $paper_id,
                    ':hod_id' => $user_id
                ]);
            }
        }

        // Log to action_logs
        $stmt_log = $pdo->prepare("
            INSERT INTO action_logs (user_id, action_type, description, paper_id)
            VALUES (:user_id, :action_type, :description, :paper_id)
        ");
        $stmt_log->execute([
            ':user_id' => $user_id,
            ':action_type' => $decision,
            ':description' => ucfirst($user_role) . " reviewed and $decision the paper. Status Updated to " . $new_status . ".",
            ':paper_id' => $paper_id
        ]);

        $pdo->commit();

        unset($_SESSION['csrf_review_action']);
        unset($_SESSION['review_verified_papers'][$paper_id]);

        // --- Success Message Before Redirect ---
        $redirect_url = 'progress.php?success=1';

        if ($decision === 'Approve') {
            if ($user_role === 'Moderator') {
                $success_msg = 'Review submitted successfully! The paper has been approved and forwarded to HOD review.';
            } else {
                $success_msg = 'Review submitted successfully! The paper has been approved and is ready for Admin printing.';
            }
        } else {
            $success_msg = 'Review submitted successfully! The paper has been rejected and feedback has been sent to the Lecturer.';
        }
?>
        <!DOCTYPE html>
        <html lang="en">

        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Review Submitted - SEPMS</title>
            <link rel="stylesheet" href="assets/css/reviewM.css">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
            <meta http-equiv="refresh" content="3;url=<?php echo htmlspecialchars($redirect_url, ENT_QUOTES, 'UTF-8'); ?>">
        </head>

        <body>
            <div class="redirect-wrapper">
                <div class="redirect-card">
                    <div class="redirect-icon">
                        <i class="fas fa-check-circle"></i>
                    </div>

                    <h2>Success!</h2>

                    <div class="msg success">
                        <?php echo htmlspecialchars($success_msg, ENT_QUOTES, 'UTF-8'); ?>
                    </div>

                    <p class="status-text">
                        New paper status:
                        <strong><?php echo htmlspecialchars($new_status, ENT_QUOTES, 'UTF-8'); ?></strong>
                    </p>

                    <p class="loading-text">Redirecting to progress page...</p>
                </div>
            </div>

            <script>
                setTimeout(function() {
                    window.location.href = <?php echo json_encode($redirect_url); ?>;
                }, 3000);
            </script>
        </body>

        </html>
<?php
        exit;
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log('Database error: ' . $e->getMessage());

        header('Location: review.php?paper_id=' . $paper_id . '&error=db_error');
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($user_role, ENT_QUOTES, 'UTF-8'); ?> Review - SEPMS</title>
    <link rel="stylesheet" href="assets/css/reviewM.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">

</head>

<body>
    <div class="dashboard-header">
        <div class="container">
            <div class="header-left">
                <div class="logout">
                    <a href="dashboard.php" class="back-link">
                        <i class="fas fa-arrow-left logout-icon"></i> Back to Dashboard
                    </a>

                    <?php if ($msg !== ''): ?>
                        <div class="msg <?php echo htmlspecialchars($msg_type, ENT_QUOTES, 'UTF-8'); ?>">
                            <?php echo htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <div class="review-container">
        <!-- Left Section -->
        <div class="left-section">
            <div class="card paper-details">
                <h3>Paper Details</h3>

                <p><strong>Title:</strong> <?php echo htmlspecialchars((string) $paper['paper_name'], ENT_QUOTES, 'UTF-8'); ?></p>
                <p><strong>Lecturer:</strong> <?php echo htmlspecialchars((string) $paper['lecturer_name'], ENT_QUOTES, 'UTF-8'); ?></p>
                <p><strong>Submitted:</strong> <?php echo htmlspecialchars((string) $paper['submission_date'], ENT_QUOTES, 'UTF-8'); ?></p>

                <div class="file-section">
                    <p>
                        <strong>Attached File:</strong>
                        <?php echo htmlspecialchars((string) $latest_file['original_name'], ENT_QUOTES, 'UTF-8'); ?>
                    </p>

                    <?php if (!empty($latest_file['stored_name'])): ?>
                        <div class="unlock-note">
                            Enter the correct decryption key first. After the key is verified, you must view and close the paper preview before the decision form is unlocked.
                        </div>

                        <form id="key-verify-form" class="decrypt-form">
                            <label for="encryption_key"><strong>Enter Decryption Key:</strong></label>

                            <input
                                type="password"
                                id="encryption_key"
                                name="encryption_key"
                                placeholder="Enter key to verify paper"
                                autocomplete="off"
                                required>

                            <button type="submit" class="view-file-btn" id="verify-key-btn">
                                Submit Key
                            </button>
                        </form>

                        <div id="key-message" class="key-message msg"></div>

                        <div id="verified-box" class="verified-box" style="<?php echo $review_unlocked ? 'display:block;' : ''; ?>">
                            <strong>Key verified.</strong> Click the button below to view the paper.
                            <br><br>
                            <button type="button" class="view-file-btn" id="view-paper-btn">
                                View Paper
                            </button>
                        </div>
                    <?php else: ?>
                        <p>No file uploaded.</p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="card review-guidelines">
                <?php if ($user_role === 'Moderator'): ?>
                    <h3>Moderator Review Guidelines</h3>
                    <ul class="guidelines-list">
                        <li class="numbered">1. Check paper format and structure</li>
                        <li>• Ensure headings, numbering, tables, figures, and sections follow the standard template.</li>
                        <li class="numbered">2. Verify content quality and accuracy</li>
                        <li>• Ensure questions are clear, unambiguous, and correct.</li>
                        <li>• Check solutions or answer keys if provided.</li>
                        <li class="numbered">3. Ensure compliance with examination standards</li>
                        <li>• Marks allocation is reasonable and consistent with syllabus.</li>
                        <li class="numbered">4. Provide constructive feedback if rejecting</li>
                        <li>• Clearly explain what needs improvement.</li>
                        <li>• Suggest specific changes to the lecturer.</li>
                        <li class="numbered">5. Approved papers will proceed to HOD review</li>
                        <li>• Only papers approved by moderators should be forwarded for HOD final approval.</li>
                    </ul>
                <?php elseif ($user_role === 'HOD'): ?>
                    <h3>HOD Review Guidelines</h3>
                    <ul class="guidelines-list">
                        <li class="numbered">1. Verify overall quality and accuracy</li>
                        <li>• Ensure content is academically sound and aligns with program standards.</li>
                        <li class="numbered">2. Check compliance with university/exam policies</li>
                        <li>• Ensure proper format, integrity, and fairness in assessment.</li>
                        <li class="numbered">3. Provide constructive feedback if rejecting</li>
                        <li>• Clearly explain required improvements or corrections.</li>
                        <li class="numbered">4. Approved papers are finalized</li>
                        <li>• Papers approved by HOD are considered ready for examination use.</li>
                    </ul>
                <?php endif; ?>
            </div>
        </div>

        <!-- Right Section -->
        <div class="right-section">
            <div class="card locked-review-card" id="locked-review-card" style="<?php echo $review_unlocked ? 'display:none;' : ''; ?>">
                <i class="fas fa-lock"></i>
                <h3><?php echo htmlspecialchars($user_role, ENT_QUOTES, 'UTF-8'); ?> Review Locked</h3>
                <p>Please enter the correct decryption key, view the paper, and close the preview before making a decision.</p>
            </div>

            <div class="card <?php echo htmlspecialchars(strtolower($user_role), ENT_QUOTES, 'UTF-8') . '-review'; ?> hidden-review-card" id="review-decision-card" style="<?php echo $review_unlocked ? 'display:block;' : ''; ?>">
                <h3><?php echo htmlspecialchars($user_role, ENT_QUOTES, 'UTF-8'); ?> Review</h3>

                <form action="review.php?paper_id=<?php echo htmlspecialchars((string) $paper_id, ENT_QUOTES, 'UTF-8'); ?>" method="POST" id="review-form">
                    <input
                        type="hidden"
                        name="csrf_token"
                        value="<?php echo htmlspecialchars($_SESSION['csrf_review_action'], ENT_QUOTES, 'UTF-8'); ?>">

                    <input
                        type="hidden"
                        name="verification_token"
                        id="verification_token"
                        value="<?php echo htmlspecialchars($existing_verification_token, ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="decision">
                        <label>Decision *</label>

                        <div>
                            <input type="radio" name="decision" value="Approve" id="Approve" required>
                            <label for="Approve" class="Approve">Approve</label>
                        </div>

                        <div>
                            <input type="radio" name="decision" value="Reject" id="reject">
                            <label for="reject" class="reject">Reject / Request Changes</label>
                        </div>
                    </div>

                    <div class="feedback">
                        <label for="feedback">Feedback</label>
                        <textarea
                            name="feedback"
                            id="feedback"
                            placeholder="Optional comments or notes about this paper..."></textarea>

                        <small id="feedback-error" style="display:none;">Feedback is required when rejecting the paper.</small>
                    </div>

                    <div class="buttons">
                        <button type="button" class="save-draft-btn" onclick="window.location.href='dashboard.php'">
                            Cancel
                        </button>

                        <button type="submit" name="submit_review" class="submit-btn">
                            Submit Review
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Paper Preview Popup -->
    <div class="paper-modal" id="paper-modal">
        <div class="paper-modal-content">
            <div class="paper-modal-header">
                <h3 id="paper-modal-title">Paper Preview</h3>
                <div class="paper-modal-actions">
                    <a href="#" id="paper-download-link" class="paper-download-link" download>
                        Download / Open File
                    </a>
                    <button type="button" class="modal-close-btn" id="close-paper-modal">
                        Close Preview
                    </button>
                </div>
            </div>
            <iframe id="paper-frame" class="paper-frame"></iframe>
        </div>
    </div>

    <script>
        const csrfToken = <?php echo json_encode($_SESSION['csrf_review_action']); ?>;
        const paperId = <?php echo json_encode((string) $paper_id); ?>;
        const originalFilename = <?php echo json_encode((string) $latest_file['original_name']); ?>;

        let verificationToken = <?php echo json_encode($existing_verification_token); ?>;
        let objectUrl = null;
        let paperWasOpened = <?php echo $review_unlocked ? 'true' : 'false'; ?>;

        const keyVerifyForm = document.getElementById("key-verify-form");
        const encryptionKeyInput = document.getElementById("encryption_key");
        const verifyKeyBtn = document.getElementById("verify-key-btn");
        const keyMessage = document.getElementById("key-message");
        const verifiedBox = document.getElementById("verified-box");
        const viewPaperBtn = document.getElementById("view-paper-btn");

        const lockedReviewCard = document.getElementById("locked-review-card");
        const reviewDecisionCard = document.getElementById("review-decision-card");
        const verificationTokenInput = document.getElementById("verification_token");

        const paperModal = document.getElementById("paper-modal");
        const paperFrame = document.getElementById("paper-frame");
        const paperDownloadLink = document.getElementById("paper-download-link");
        const paperModalTitle = document.getElementById("paper-modal-title");
        const closePaperModal = document.getElementById("close-paper-modal");

        function showKeyMessage(message, type) {
            keyMessage.textContent = message;
            keyMessage.className = "key-message msg " + type;
        }

        function unlockDecisionForm() {
            lockedReviewCard.style.display = "none";
            reviewDecisionCard.style.display = "block";
        }

        if (keyVerifyForm) {
            keyVerifyForm.addEventListener("submit", async function(event) {
                event.preventDefault();

                const key = encryptionKeyInput.value.trim();

                if (!key) {
                    showKeyMessage("Please enter the decryption key.", "error");
                    return;
                }

                verifyKeyBtn.disabled = true;
                verifyKeyBtn.textContent = "Checking...";
                showKeyMessage("Checking decryption key...", "success");

                try {
                    const response = await fetch("review.php?paper_id=" + encodeURIComponent(paperId), {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/x-www-form-urlencoded"
                        },
                        body: new URLSearchParams({
                            ajax_action: "verify_key",
                            csrf_token: csrfToken,
                            encryption_key: key
                        })
                    });

                    const result = await response.json();

                    if (!response.ok || !result.success) {
                        throw new Error(result.message || "Incorrect decryption key.");
                    }

                    verificationToken = result.token;
                    verificationTokenInput.value = verificationToken;

                    showKeyMessage(result.message, "success");
                    verifiedBox.style.display = "block";
                    encryptionKeyInput.disabled = true;
                    verifyKeyBtn.textContent = "Key Verified";
                } catch (error) {
                    showKeyMessage(error.message, "error");
                    verifyKeyBtn.disabled = false;
                    verifyKeyBtn.textContent = "Submit Key";
                }
            });
        }

        if (viewPaperBtn) {
            viewPaperBtn.addEventListener("click", async function() {
                if (!verificationToken) {
                    showKeyMessage("Please verify the decryption key first.", "error");
                    return;
                }

                viewPaperBtn.disabled = true;
                viewPaperBtn.textContent = "Opening...";

                try {
                    const response = await fetch("review.php?paper_id=" + encodeURIComponent(paperId), {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/x-www-form-urlencoded"
                        },
                        body: new URLSearchParams({
                            ajax_action: "view_file",
                            csrf_token: csrfToken,
                            verification_token: verificationToken
                        })
                    });

                    if (!response.ok) {
                        const errorText = await response.text();
                        throw new Error(errorText || "Unable to open paper.");
                    }

                    const fileBlob = await response.blob();

                    if (objectUrl) {
                        URL.revokeObjectURL(objectUrl);
                    }

                    objectUrl = URL.createObjectURL(fileBlob);
                    paperFrame.src = objectUrl;
                    paperDownloadLink.href = objectUrl;
                    paperDownloadLink.download = originalFilename;
                    paperModalTitle.textContent = "Paper Preview - " + originalFilename;
                    paperModal.classList.add("active");
                    paperWasOpened = true;
                } catch (error) {
                    showKeyMessage(error.message, "error");
                } finally {
                    viewPaperBtn.disabled = false;
                    viewPaperBtn.textContent = "View Paper";
                }
            });
        }

        closePaperModal.addEventListener("click", function() {
            paperModal.classList.remove("active");
            paperFrame.src = "";

            if (objectUrl) {
                URL.revokeObjectURL(objectUrl);
                objectUrl = null;
            }

            if (paperWasOpened) {
                unlockDecisionForm();
            }
        });

        paperModal.addEventListener("click", function(event) {
            if (event.target === paperModal) {
                closePaperModal.click();
            }
        });

        const approveRadio = document.getElementById("Approve");
        const rejectRadio = document.getElementById("reject");
        const feedbackField = document.getElementById("feedback");
        const feedbackError = document.getElementById("feedback-error");
        const reviewForm = document.getElementById("review-form");

        function updateFeedbackRequirement() {
            if (rejectRadio.checked) {
                feedbackField.setAttribute("required", "required");
                feedbackError.style.display = feedbackField.value.trim() ? "none" : "block";
            } else {
                feedbackField.removeAttribute("required");
                feedbackError.style.display = "none";
            }
        }

        document.addEventListener("DOMContentLoaded", updateFeedbackRequirement);
        approveRadio.addEventListener("change", updateFeedbackRequirement);
        rejectRadio.addEventListener("change", updateFeedbackRequirement);

        feedbackField.addEventListener("input", function() {
            if (rejectRadio.checked) {
                feedbackError.style.display = feedbackField.value.trim() ? "none" : "block";
            }
        });

        reviewForm.addEventListener("submit", function(event) {
            if (!verificationTokenInput.value) {
                event.preventDefault();
                alert("Please enter the correct key and view the paper before submitting a decision.");
                return;
            }

            if (rejectRadio.checked && !feedbackField.value.trim()) {
                event.preventDefault();
                feedbackError.style.display = "block";
                feedbackField.focus();
                return;
            }

            feedbackError.style.display = "none";
        });
    </script>
</body>

</html>