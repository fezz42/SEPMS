<?php

declare(strict_types=1);
session_start();

require_once 'includes/db.php';

if (!isset($_SESSION['user'])) {
    header('Location: index.php?error=unauthorized');
    exit;
}

$user = $_SESSION['user'];
$userId = (int) ($user['id'] ?? 0);
$userRole = trim((string) ($user['role'] ?? ''));
$fullName = $user['full_name'] ?? 'User';
$userCollege = trim((string) ($user['college'] ?? ''));

$allowedRoles = ['Lecturer', 'Moderator', 'HOD', 'Admin'];
if (!in_array($userRole, $allowedRoles, true)) {
    header('Location: index.php?error=invalid_role');
    exit;
}

$pdo = db();

if ($userRole === 'Admin' && empty($_SESSION['csrf_mark_printed'])) {
    $_SESSION['csrf_mark_printed'] = bin2hex(random_bytes(32));
}

$stats = [];
$papers = [];
$pendingPapers = [];
$approvedPapers = [];
$successMessage = '';
$errorMessage = '';

/**
 * Admin mark as printed using POST + CSRF
 */
if (
    $userRole === 'Admin' &&
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['action'], $_POST['paper_id']) &&
    $_POST['action'] === 'mark_printed'
) {
    if (
        empty($_POST['csrf_token']) ||
        empty($_SESSION['csrf_mark_printed']) ||
        !hash_equals($_SESSION['csrf_mark_printed'], (string) $_POST['csrf_token'])
    ) {
        header('Location: dashboard.php?error=invalid_csrf');
        exit;
    }

    if (!ctype_digit((string) $_POST['paper_id'])) {
        header('Location: dashboard.php?error=invalid_paper');
        exit;
    }

    $paperId = (int) $_POST['paper_id'];

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare("
            UPDATE papers
            SET printed_status = 'Printed'
            WHERE id = :paper_id 
              AND status = 'Approved' 
              AND printed_status != 'Printed'
        ");
        $stmt->execute([':paper_id' => $paperId]);

        $logStmt = $pdo->prepare("
            INSERT INTO action_logs (user_id, action_type, description, paper_id)
            VALUES (:user_id, :action_type, :description, :paper_id)
        ");
        $logStmt->execute([
            ':user_id' => $userId,
            ':action_type' => 'Mark as Printed',
            ':description' => 'Admin marked paper ID ' . $paperId . ' as printed.',
            ':paper_id' => $paperId,
        ]);

        $pdo->commit();

        unset($_SESSION['csrf_mark_printed']);

        header('Location: dashboard.php?success=printed');
        exit;
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log($e->getMessage());
        header('Location: dashboard.php?error=db');
        exit;
    }
}

if (isset($_GET['success']) && $_GET['success'] === 'printed') {
    $successMessage = 'Paper marked as printed successfully.';
}

if (isset($_GET['error']) && $_GET['error'] === 'db') {
    $errorMessage = 'Database error occurred. Please try again.';
}

if (isset($_GET['error']) && $_GET['error'] === 'invalid_csrf') {
    $errorMessage = 'Invalid request. Please try again.';
}

if (isset($_GET['error']) && $_GET['error'] === 'invalid_paper') {
    $errorMessage = 'Invalid paper selected.';
}

try {
    if ($userRole === 'Lecturer') {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) AS total_papers,
                COALESCE(SUM(CASE WHEN status = 'Pending Moderator Review' THEN 1 ELSE 0 END), 0) AS pending_moderator,
                COALESCE(SUM(CASE WHEN status = 'Pending HOD Review' THEN 1 ELSE 0 END), 0) AS pending_hod,
                COALESCE(SUM(CASE WHEN status = 'Approved' THEN 1 ELSE 0 END), 0) AS approved,
                COALESCE(SUM(CASE WHEN status IN ('Rejected by Moderator', 'Rejected by HOD') THEN 1 ELSE 0 END), 0) AS action_required
            FROM papers
            WHERE lecturer_id = :lecturer_id
        ");
        $stmt->execute([':lecturer_id' => $userId]);
        $stats = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];

        $stmt = $pdo->prepare("
            SELECT id, paper_name, status, submission_date
            FROM papers
            WHERE lecturer_id = :lecturer_id
            ORDER BY submission_date DESC
        ");
        $stmt->execute([':lecturer_id' => $userId]);
        $papers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    if ($userRole === 'Moderator') {
        $stmt = $pdo->prepare("
        SELECT 
            COALESCE(SUM(CASE WHEN p.status = 'Pending Moderator Review' THEN 1 ELSE 0 END), 0) AS pending_review,
            COALESCE(COUNT(DISTINCT CASE WHEN pa.action IS NOT NULL THEN pa.paper_id END), 0) AS total_reviewed,
            COALESCE(COUNT(DISTINCT CASE WHEN pa.action = 'Approved' THEN pa.paper_id END), 0) AS review_approved
        FROM papers p
        JOIN users lecturer ON lecturer.id = p.lecturer_id
        LEFT JOIN paper_actions pa 
            ON p.id = pa.paper_id 
           AND pa.actor_role = 'Moderator'
        WHERE p.moderator_id = :moderator_id
          AND lecturer.college = :college
    ");

        $stmt->execute([
            ':moderator_id' => $userId,
            ':college' => $userCollege
        ]);

        $stats = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];

        $stmt = $pdo->prepare("
        SELECT 
            p.id,
            p.paper_name,
            p.submission_date,
            p.status,
            lecturer.full_name AS lecturer_name
        FROM papers p
        JOIN users lecturer ON p.lecturer_id = lecturer.id
        WHERE p.status = 'Pending Moderator Review'
          AND p.moderator_id = :moderator_id
          AND lecturer.college = :college
        ORDER BY p.submission_date DESC
    ");

        $stmt->execute([
            ':moderator_id' => $userId,
            ':college' => $userCollege
        ]);

        $pendingPapers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    if ($userRole === 'HOD') {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(CASE WHEN status = 'Pending HOD Review' THEN 1 END) AS pending_review,
                COUNT(CASE WHEN status IN ('Approved', 'Rejected by HOD') THEN 1 END) AS total_reviewed,
                COUNT(CASE WHEN status = 'Approved' THEN 1 END) AS review_approved
            FROM papers
        ");
        $stmt->execute();
        $stats = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];

        $stmt = $pdo->prepare("
            SELECT 
                p.id,
                p.paper_name,
                p.submission_date,
                p.status,
                u.full_name AS lecturer_name
            FROM papers p
            JOIN users u ON p.lecturer_id = u.id
            WHERE p.status = 'Pending HOD Review'
            ORDER BY p.submission_date DESC
        ");
        $stmt->execute();
        $pendingPapers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    if ($userRole === 'Admin') {
        $stmt = $pdo->query("SELECT COUNT(*) FROM users");
        $totalUsers = (int) $stmt->fetchColumn();

        $stmt = $pdo->query("SELECT COUNT(*) FROM papers WHERE status = 'Approved'");
        $totalApproved = (int) $stmt->fetchColumn();

        $stmt = $pdo->query("SELECT COUNT(*) FROM papers WHERE printed_status = 'Printed'");
        $totalPrinted = (int) $stmt->fetchColumn();

        $stmt = $pdo->query("SELECT COUNT(*) FROM papers WHERE status = 'Approved' AND printed_status = 'Pending'");
        $totalPendingPrint = (int) $stmt->fetchColumn();

        $stats = [
            'total_users' => $totalUsers,
            'total_approved' => $totalApproved,
            'total_printed' => $totalPrinted,
            'total_pending_print' => $totalPendingPrint,
        ];


        $stmt = $pdo->prepare("
    SELECT 
    p.id,
    p.paper_name,
    p.status,
    u.full_name AS lecturer_name,
    m.full_name AS moderator_name,
    h.full_name AS hod_name,
    p.updated_at,
    p.printed_status
FROM papers p
JOIN users u ON u.id = p.lecturer_id
LEFT JOIN users m ON m.id = p.moderator_id
LEFT JOIN users h ON h.id = p.hod_id
WHERE p.status = 'Approved'
ORDER BY p.updated_at DESC;
");
        $stmt->execute();
        $approvedPapers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
} catch (PDOException $e) {
    // Log error details to a file
    error_log("Error message: " . $e->getMessage(), 3, 'error_log.txt');
    $errorMessage = 'Failed to load dashboard data. Please check the logs.';
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
?>


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= e($userRole) ?> Dashboard - SEPMS</title>
    <link rel="stylesheet" href="assets/css/dashboard.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
</head>

<body>

    <div class="dashboard-header">
        <div class="container">
            <div class="header-left">
                <div class="logo-container">
                    <img src="assets/images/logo.png" alt="SEPMS Logo" class="logo">
                </div>
                <div class="header-text">
                    <h1><?= e($userRole) ?> Dashboard</h1>
                    <p>Welcome, <?= e($fullName) ?></p>
                </div>
            </div>
            <div class="logout">
                <a href="includes/logout.php">
                    <i class="fas fa-door-open logout-icon"></i> Logout
                </a>
            </div>
        </div>
    </div>


    <div class="dashboard-stats">
        <div class="container">

            <?php if ($userRole === 'Lecturer'): ?>
                <div class="stat-card">
                    <div class="stat-info">
                        <p>Paper Submitted</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #daefff;">
                                <i class="fa-regular fa-file-lines" style="color: #0091ff;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['total_papers'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Pending Moderator</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #fff4dd;">
                                <i class="fa-regular fa-clock" style="color: #db8e00;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['pending_moderator'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Action Required</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #ffe1e1;">
                                <i class="fa-regular fa-pen-to-square" style="color: #ff0000;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['action_required'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Pending HOD</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #f9dfff;">
                                <i class="fa-regular fa-clock" style="color: #b700ff;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['pending_hod'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Paper Approved</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #dfffdf;">
                                <i class="fa-regular fa-circle-check" style="color: #009e00;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['approved'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($userRole === 'Moderator'): ?>
                <div class="stat-card">
                    <div class="stat-info">
                        <p>Pending Review</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #fff9d7;">
                                <i class="fa-regular fa-clipboard" style="color: #f0bc00;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['pending_review'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Total Reviewed</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #daeeff;">
                                <i class="fa-regular fa-clipboard" style="color: #0026ff;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['total_reviewed'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Review Approved</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #d4ffde;">
                                <i class="fa-regular fa-clipboard" style="color: #00d335;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['review_approved'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($userRole === 'HOD'): ?>
                <div class="stat-card">
                    <div class="stat-info">
                        <p>Pending Review</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #e3edff;">
                                <i class="fa-regular fa-circle-check" style="color: #005eff;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['pending_review'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Total Reviewed</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #fde3ff;">
                                <i class="fa-regular fa-circle-check" style="color: #ea00ff;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['total_reviewed'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Review Approved</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #e4ffe2;">
                                <i class="fa-regular fa-circle-check" style="color: #15ff00;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['review_approved'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($userRole === 'Admin'): ?>
                <div class="stat-card">
                    <div class="stat-info">
                        <p>Total Users</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #edeeff;">
                                <i class="fa-regular fa-user" style="color: #000ead;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['total_users'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Total Approved</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #e1ffe3;">
                                <i class="fa-regular fa-circle-check" style="color: #00aa08;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['total_approved'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Printed</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #fde3ff;">
                                <i class="fa-solid fa-print" style="color: #ea00ff;"></i>

                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['total_printed'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-info">
                        <p>Pending Print</p>
                        <div class="stat-content">
                            <div class="stat-icon" style="background-color: #fff9d9;">
                                <i class="fa-regular fa-circle-check" style="color: #dcb906;"></i>
                            </div>
                            <div class="stat-number">
                                <h3><?= (int) ($stats['total_pending_print'] ?? 0) ?></h3>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

        </div>
    </div>

    <div class="container">
        <div class="dashboard-actions">
            <?php if ($userRole === 'Lecturer'): ?>
                <button onclick="window.location.href='submit.php'" class="btn-submit">
                    <i class="fa-solid fa-arrow-up-from-bracket" style="color: #ffffff; padding-right: 10px;"></i>
                    Submit New Paper
                </button>

                <button onclick="window.location.href='progress.php'" class="btn-view">
                    <i class="fa-solid fa-chart-column" style="color: #000000; padding-right: 10px;"></i>
                    View Progress
                </button>
            <?php endif; ?>

            <?php if ($userRole === 'Moderator'): ?>
                <button onclick="window.location.href='progress.php'" class="btn-view">
                    <i class="fa-solid fa-chart-column" style="color: #000000; padding-right: 10px;"></i>
                    View Progress
                </button>
            <?php endif; ?>

            <?php if ($userRole === 'HOD'): ?>
                <button onclick="window.location.href='progress.php'" class="btn-view">
                    <i class="fa-solid fa-chart-column" style="color: #000000; padding-right: 10px;"></i>
                    View Progress
                </button>
            <?php endif; ?>

            <?php if ($userRole === 'Admin'): ?>
                <button onclick="window.location.href='admin/userManagement.php'" class="btn-submit">
                    <i class="fa-solid fa-arrow-up-from-bracket" style="color: #ffffff; padding-right: 10px;"></i>
                    User Management
                </button>

                <button onclick="window.location.href='admin/auditLogs.php'" class="btn-view">
                    <i class="fa-solid fa-chart-column" style="color: #000000; padding-right: 10px;"></i>
                    Audit Logs
                </button>

                <button onclick="window.location.href='admin/approval.php'" class="btn-view">
                    <i class="fa-solid fa-chart-column" style="color: #000000; padding-right: 10px;"></i>
                    New Registration
                </button>
                <button onclick="window.location.href='admin/subjectManagement.php'" class="btn-view">
                    <i class="fa-solid fa-book" style="color: #000000; padding-right: 10px;"></i>
                    Subject Management
                </button>
            <?php endif; ?>
        </div>
    </div>

    <div class="container">
        <div class="exam-papers-table">
            <?php if ($successMessage !== ''): ?>
                <div class="msg success"><?= e($successMessage) ?></div>
            <?php endif; ?>

            <?php if ($errorMessage !== ''): ?>
                <div class="msg error"><?= e($errorMessage) ?></div>
            <?php endif; ?>

            <?php if ($userRole === 'Lecturer'): ?>
                <h3>My Exam Papers</h3>

                <?php if (empty($papers)): ?>
                    <p class="empty-state">No papers submitted yet. Click "Submit New Paper" to get started.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Paper Name</th>
                                    <th>Status</th>
                                    <th>Submission Date</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($papers as $paper): ?>
                                    <?php
                                    $isRejected = in_array($paper['status'], [
                                        'Rejected by Moderator',
                                        'Rejected by HOD'
                                    ], true);
                                    ?>
                                    <tr>
                                        <td><?= e((string) $paper['paper_name']) ?></td>
                                        <td><?= e((string) $paper['status']) ?></td>
                                        <td><?= e((string) $paper['submission_date']) ?></td>
                                        <td>
                                            <?php if ($isRejected): ?>
                                                <button class="btn-action"
                                                    onclick="window.location.href='submit.php?paper_id=<?= (int) $paper['id'] ?>'">
                                                    Resubmit
                                                </button>
                                            <?php else: ?>
                                                <button class="btn-action"
                                                    onclick="window.location.href='progress.php?paper_id=<?= (int) $paper['id'] ?>'">
                                                    View
                                                </button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($userRole === 'Moderator'): ?>
                <h3>Papers Awaiting Review</h3>

                <?php if (empty($pendingPapers)): ?>
                    <p class="empty-state">No papers are currently pending review.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Paper Name</th>
                                    <th>Lecturer</th>
                                    <th>Submission Date</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($pendingPapers as $paper): ?>
                                    <tr>
                                        <td><?= e((string) $paper['paper_name']) ?></td>
                                        <td><?= e((string) $paper['lecturer_name']) ?></td>
                                        <td><?= date("M d, Y", strtotime((string) $paper['submission_date'])) ?></td>
                                        <td><?= e((string) $paper['status']) ?></td>
                                        <td>
                                            <button class="btn-review"
                                                onclick="window.location.href='review.php?paper_id=<?php echo $paper['id']; ?>'">
                                                Review
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($userRole === 'HOD'): ?>
                <h3>Papers Awaiting Review</h3>

                <?php if (empty($pendingPapers)): ?>
                    <p class="empty-state">No papers awaiting review.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Paper Name</th>
                                    <th>Lecturer</th>
                                    <th>Submission Date</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($pendingPapers as $paper): ?>
                                    <tr>
                                        <td><?= e((string) $paper['paper_name']) ?></td>
                                        <td><?= e((string) $paper['lecturer_name']) ?></td>
                                        <td><?= date("M d, Y", strtotime((string) $paper['submission_date'])) ?></td>
                                        <td><?= e((string) $paper['status']) ?></td>
                                        <td>
                                            <button class="btn-review"
                                                onclick="window.location.href='review.php?paper_id=<?php echo $paper['id']; ?>'">
                                                Review
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($userRole === 'Admin'): ?>
                <h3>Approved Papers</h3>

                <?php if (empty($approvedPapers)): ?>
                    <p class="empty-state">No approved papers found.</p>
                <?php else: ?>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Paper Name</th>
                                    <th>Lecturer</th>
                                    <th>Moderator</th>
                                    <th>HOD</th>
                                    <th>Approval Date</th>
                                    <th>Status</th>
                                    <th style="text-align: center;">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($approvedPapers as $paper): ?>
                                    <tr>
                                        <td><?= e($paper['paper_name']) ?></td>
                                        <td><?= e($paper['lecturer_name']) ?></td>
                                        <td><?= e($paper['moderator_name'] ?? '-') ?></td>
                                        <td><?= e($paper['hod_name'] ?? '-') ?></td>
                                        <td><?= e($paper['updated_at'] ?? '-') ?></td>
                                        <td><?= e($paper['status']) ?></td>
                                        <td>
                                            <div class="admin-print-actions">
                                                <button type="button"
                                                    class="btn-print-paper"
                                                    onclick="window.open('print.php?paper_id=<?= (int) $paper['id'] ?>', '_blank')">
                                                    <i class="fa-solid fa-print"></i>
                                                    Print
                                                </button>

                                                <?php if (($paper['printed_status'] ?? 'Pending') !== 'Printed'): ?>
                                                    <form method="POST" action="dashboard.php" style="display:inline;">
                                                        <input type="hidden" name="action" value="mark_printed">
                                                        <input
                                                            type="hidden"
                                                            name="paper_id"
                                                            value="<?= (int) $paper['id'] ?>">
                                                        <input
                                                            type="hidden"
                                                            name="csrf_token"
                                                            value="<?= e($_SESSION['csrf_mark_printed']) ?>">

                                                        <button
                                                            type="submit"
                                                            class="btn-mark-printed"
                                                            onclick="return confirm('Are you sure you want to mark this paper as printed?');">
                                                            <i class="fa-solid fa-check"></i>
                                                            Mark as Printed
                                                        </button>
                                                    </form>
                                                <?php else: ?>
                                                    <span class="printed-label">
                                                        <i class="fa-solid fa-circle-check"></i>
                                                        Printed
                                                    </span>
                                                <?php endif; ?>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

        </div>
    </div>


</body>

</html>