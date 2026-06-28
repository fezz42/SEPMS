<?php

declare(strict_types=1);
session_start();

require_once '../includes/db.php';

if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Admin') {
    header('Location: ../index.php?error=unauthorized');
    exit;
}

if (empty($_SESSION['csrf_subject_action'])) {
    $_SESSION['csrf_subject_action'] = bin2hex(random_bytes(32));
}

$pdo = db();
$admin_id = (int) $_SESSION['user']['id'];

$msg = '';
$msg_type = '';

if (isset($_GET['success'])) {
    $success = [
        'added' => 'Subject added successfully.',
        'updated' => 'Subject updated successfully.',
        'deleted' => 'Subject deleted successfully.'
    ];

    $msg = $success[$_GET['success']] ?? 'Action completed successfully.';
    $msg_type = 'success';
} elseif (isset($_GET['error'])) {
    $errors = [
        'invalid_request' => 'Invalid request. Please try again.',
        'invalid_csrf' => 'Invalid request token. Please refresh and try again.',
        'required' => 'Please complete all required fields.',
        'invalid_college' => 'Invalid college selected.',
        'invalid_moderator' => 'Invalid moderator selected. Moderator must be active, approved, and from the selected college.',
        'duplicate' => 'This subject code already exists for the selected college.',
        'db_error' => 'Database error. Please try again.'
    ];

    $msg = $errors[$_GET['error']] ?? 'Something went wrong. Please try again.';
    $msg_type = 'error';
}

// Handle add subject
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (
        empty($_POST['csrf_token']) ||
        empty($_SESSION['csrf_subject_action']) ||
        !hash_equals($_SESSION['csrf_subject_action'], (string) $_POST['csrf_token'])
    ) {
        header('Location: subjectManagement.php?error=invalid_csrf');
        exit;
    }

    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'add_subject') {
        $subject_code = strtoupper(trim((string) ($_POST['subject_code'] ?? '')));
        $subject_name = trim((string) ($_POST['subject_name'] ?? ''));
        $college = trim((string) ($_POST['college'] ?? ''));
        $moderator_id = isset($_POST['moderator_id']) ? (int) $_POST['moderator_id'] : 0;

        if ($subject_code === '' || $subject_name === '' || $college === '' || $moderator_id === 0) {
            header('Location: subjectManagement.php?error=required');
            exit;
        }

        if (!in_array($college, ['CCI', 'COE', 'COBA'], true)) {
            header('Location: subjectManagement.php?error=invalid_college');
            exit;
        }

        try {
            // Validate moderator belongs to selected college
            $stmt_mod = $pdo->prepare("
                SELECT id
                FROM users
                WHERE id = :moderator_id
                  AND role = 'Moderator'
                  AND college = :college
                  AND registration = 'approved'
                  AND status = 'active'
                LIMIT 1
            ");
            $stmt_mod->execute([
                ':moderator_id' => $moderator_id,
                ':college' => $college
            ]);

            if (!$stmt_mod->fetchColumn()) {
                header('Location: subjectManagement.php?error=invalid_moderator');
                exit;
            }

            $pdo->beginTransaction();

            $stmt = $pdo->prepare("
                INSERT INTO subjects (
                    subject_code,
                    subject_name,
                    college,
                    moderator_id,
                    status
                )
                VALUES (
                    :subject_code,
                    :subject_name,
                    :college,
                    :moderator_id,
                    'active'
                )
            ");

            $stmt->execute([
                ':subject_code' => $subject_code,
                ':subject_name' => $subject_name,
                ':college' => $college,
                ':moderator_id' => $moderator_id
            ]);

            $stmt_log = $pdo->prepare("
                INSERT INTO action_logs (user_id, action_type, description)
                VALUES (:user_id, :action_type, :description)
            ");
            $stmt_log->execute([
                ':user_id' => $admin_id,
                ':action_type' => 'Add Subject',
                ':description' => 'Admin added subject ' . $subject_code . ' - ' . $subject_name . '.'
            ]);

            $pdo->commit();

            header('Location: subjectManagement.php?success=added');
            exit;
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            error_log('Subject add error: ' . $e->getMessage());

            if ((int) ($e->errorInfo[1] ?? 0) === 1062) {
                header('Location: subjectManagement.php?error=duplicate');
                exit;
            }

            header('Location: subjectManagement.php?error=db_error');
            exit;
        }
    }

    if ($action === 'delete_subject') {
        $subject_id = isset($_POST['subject_id']) && ctype_digit((string) $_POST['subject_id'])
            ? (int) $_POST['subject_id']
            : 0;

        if ($subject_id === 0) {
            header('Location: subjectManagement.php?error=invalid_request');
            exit;
        }

        try {
            $pdo->beginTransaction();

            $stmt = $pdo->prepare("DELETE FROM subjects WHERE id = :subject_id");
            $stmt->execute([':subject_id' => $subject_id]);

            $stmt_log = $pdo->prepare("
                INSERT INTO action_logs (user_id, action_type, description)
                VALUES (:user_id, :action_type, :description)
            ");
            $stmt_log->execute([
                ':user_id' => $admin_id,
                ':action_type' => 'Delete Subject',
                ':description' => 'Admin deleted subject ID ' . $subject_id . '.'
            ]);

            $pdo->commit();

            header('Location: subjectManagement.php?success=deleted');
            exit;
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            error_log('Subject delete error: ' . $e->getMessage());
            header('Location: subjectManagement.php?error=db_error');
            exit;
        }
    }

    header('Location: subjectManagement.php?error=invalid_request');
    exit;
}

// Fetch moderators
$stmt_moderators = $pdo->prepare("
    SELECT id, full_name, college
    FROM users
    WHERE role = 'Moderator'
      AND registration = 'approved'
      AND status = 'active'
    ORDER BY college, full_name
");
$stmt_moderators->execute();
$moderators = $stmt_moderators->fetchAll(PDO::FETCH_ASSOC);

// Fetch subjects
$stmt_subjects = $pdo->prepare("
    SELECT 
        s.id,
        s.subject_code,
        s.subject_name,
        s.college,
        s.status,
        s.created_at,
        u.full_name AS moderator_name
    FROM subjects s
    JOIN users u ON s.moderator_id = u.id
    ORDER BY s.college, s.subject_code
");
$stmt_subjects->execute();
$subjects = $stmt_subjects->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subject Management - SEPMS</title>

    <link rel="stylesheet" href="../assets/css/um.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
</head>

<body>

    <div class="dashboard-header">
        <div class="container">
            <div class="header-left">
                <div class="logout">
                    <a href="../dashboard.php" class="back-link">
                        <i class="fas fa-arrow-left logout-icon"></i> Back to Dashboard
                    </a>
                </div>
            </div>
        </div>
    </div>

    <div class="container" style="margin-top: 20px;">
        <div class="exam-papers-table">
            <h3>Subject Management</h3>
            <p>Add subjects and assign one moderator to each subject.</p>

            <?php if ($msg !== ''): ?>
                <div class="msg <?= htmlspecialchars($msg_type, ENT_QUOTES, 'UTF-8'); ?>">
                    <?= htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="subjectManagement.php" class="subject-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_subject_action'], ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="action" value="add_subject">

                <div>
                    <label>Subject Code</label>
                    <input type="text" name="subject_code" placeholder="e.g. CSC101" required>
                </div>

                <div>
                    <label>Subject Name</label>
                    <input type="text" name="subject_name" placeholder="e.g. Web Programming" required>
                </div>

                <div>
                    <label>College</label>
                    <select name="college" id="college-select" required>
                        <option value="">Select College</option>
                        <option value="CCI">CCI</option>
                        <option value="COE">COE</option>
                        <option value="COBA">COBA</option>
                    </select>
                </div>

                <div>
                    <label>Moderator</label>
                    <select name="moderator_id" id="moderator-select" required>
                        <option value="">Select Moderator</option>
                        <?php foreach ($moderators as $moderator): ?>
                            <option
                                value="<?= htmlspecialchars((string) $moderator['id'], ENT_QUOTES, 'UTF-8'); ?>"
                                data-college="<?= htmlspecialchars((string) $moderator['college'], ENT_QUOTES, 'UTF-8'); ?>">
                                <?= htmlspecialchars($moderator['full_name'] . ' (' . $moderator['college'] . ')', ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <button type="submit">
                    Add Subject
                </button>
            </form>

            <table class="user-table">
                <thead>
                    <tr>
                        <th>Subject Code</th>
                        <th>Subject Name</th>
                        <th>College</th>
                        <th>Assigned Moderator</th>
                        <th>Created</th>
                        <th>Action</th>
                    </tr>
                </thead>

                <tbody>
                    <?php if (empty($subjects)): ?>
                        <tr>
                            <td colspan="7">No subjects added yet.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($subjects as $subject): ?>
                            <tr>
                                <td><?= htmlspecialchars($subject['subject_code'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?= htmlspecialchars($subject['subject_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?= htmlspecialchars($subject['college'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?= htmlspecialchars($subject['moderator_name'], ENT_QUOTES, 'UTF-8'); ?></td>

                                <td><?= htmlspecialchars($subject['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <form method="POST" action="subjectManagement.php" onsubmit="return confirm('Delete this subject?');">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_subject_action'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="action" value="delete_subject">
                                        <input type="hidden" name="subject_id" value="<?= htmlspecialchars((string) $subject['id'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <button type="submit" class="delete-btn">
                                            Delete
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const collegeSelect = document.getElementById('college-select');
        const moderatorSelect = document.getElementById('moderator-select');
        const moderatorOptions = Array.from(moderatorSelect.options);

        collegeSelect.addEventListener('change', function() {
            const selectedCollege = this.value;

            moderatorSelect.innerHTML = '';
            moderatorSelect.appendChild(moderatorOptions[0]);

            moderatorOptions.slice(1).forEach(option => {
                if (option.dataset.college === selectedCollege) {
                    moderatorSelect.appendChild(option);
                }
            });

            moderatorSelect.value = '';
        });
    </script>

</body>

</html>