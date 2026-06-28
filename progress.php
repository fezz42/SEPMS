<?php

declare(strict_types=1);
session_start();

require_once 'includes/db.php';

if (!isset($_SESSION['user'])) {
    header('Location: index.php?error=unauthorized');
    exit;
}

$pdo = db();

$sessionUserId = (int) ($_SESSION['user']['id'] ?? 0);

$stmtUser = $pdo->prepare("
    SELECT id, full_name, role, college
    FROM users
    WHERE id = :id
    LIMIT 1
");
$stmtUser->execute([':id' => $sessionUserId]);
$currentUser = $stmtUser->fetch(PDO::FETCH_ASSOC);

if (!$currentUser) {
    header('Location: index.php?error=unauthorized');
    exit;
}

$userRole = trim((string) ($currentUser['role'] ?? ''));
$userId = (int) ($currentUser['id'] ?? 0);
$userCollege = trim((string) ($currentUser['college'] ?? ''));

$allowedRoles = ['Lecturer', 'Moderator', 'HOD', 'Admin'];
if (!in_array($userRole, $allowedRoles, true)) {
    header('Location: index.php?error=invalid_role');
    exit;
}

$papers = [];
$paperDetails = null;
$paperActions = [];
$errorMessage = '';

function e(?string $value): string
{
    return htmlspecialchars((string) ($value ?? ''), ENT_QUOTES, 'UTF-8');
}

try {
    if ($userRole === 'Lecturer') {
        $stmt = $pdo->prepare("
            SELECT 
                p.id,
                p.paper_name,
                p.paper_description,
                p.status,
                p.submission_date,
                lecturer.full_name AS lecturer_name,
                moderator.full_name AS moderator_name,
                (
                    SELECT hod.full_name
                    FROM users hod
                    WHERE hod.role = 'HOD'
                    AND hod.college = lecturer.college
                    ORDER BY hod.id ASC
                    LIMIT 1
                ) AS hod_name
            FROM papers p
            INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
            LEFT JOIN users moderator ON moderator.id = p.moderator_id
            WHERE p.lecturer_id = :lecturer_id
            ORDER BY p.submission_date DESC
        ");

        $stmt->execute([
            ':lecturer_id' => $userId
        ]);

        $papers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } elseif ($userRole === 'Moderator') {
        $stmt = $pdo->prepare("
            SELECT 
                p.id,
                p.paper_name,
                p.paper_description,
                p.status,
                p.submission_date,
                lecturer.full_name AS lecturer_name,
                moderator.full_name AS moderator_name,
                (
                    SELECT hod.full_name
                    FROM users hod
                    WHERE hod.role = 'HOD'
                    AND hod.college = lecturer.college
                    ORDER BY hod.id ASC
                    LIMIT 1
                ) AS hod_name
            FROM papers p
            INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
            LEFT JOIN users moderator ON moderator.id = p.moderator_id
            WHERE p.moderator_id = :moderator_id
            AND lecturer.college = :college
            AND p.status IN (
                    'Pending Moderator Review',
                    'Pending HOD Review',
                    'Approved',
                    'Rejected by Moderator',
                    'Rejected by HOD',
                    'Printed'
            )
            ORDER BY p.submission_date DESC
        ");

        $stmt->execute([
            ':moderator_id' => $userId,
            ':college' => $userCollege
        ]);

        $papers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } elseif ($userRole === 'HOD') {
        $stmt = $pdo->prepare("
            SELECT 
                p.id,
                p.paper_name,
                p.paper_description,
                p.status,
                p.submission_date,
                lecturer.full_name AS lecturer_name,
                moderator.full_name AS moderator_name,
                (
                    SELECT hod.full_name
                    FROM users hod
                    WHERE hod.role = 'HOD'
                    AND hod.college = lecturer.college
                    ORDER BY hod.id ASC
                    LIMIT 1
                ) AS hod_name
            FROM papers p
            INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
            LEFT JOIN users moderator ON moderator.id = p.moderator_id
            WHERE lecturer.college = :college
            AND p.status IN (
                    'Pending HOD Review',
                    'Approved',
                    'Rejected by HOD',
                    'Printed'
            )
            ORDER BY p.submission_date DESC
        ");

        $stmt->execute([
            ':college' => $userCollege
        ]);

        $papers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } elseif ($userRole === 'Admin') {
        $stmt = $pdo->prepare("
            SELECT 
                p.id,
                p.paper_name,
                p.paper_description,
                p.status,
                p.submission_date,
                lecturer.full_name AS lecturer_name,
                moderator.full_name AS moderator_name,
                (
                    SELECT hod.full_name
                    FROM users hod
                    WHERE hod.role = 'HOD'
                    AND hod.college = lecturer.college
                    ORDER BY hod.id ASC
                    LIMIT 1
                ) AS hod_name
            FROM papers p
            INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
            LEFT JOIN users moderator ON moderator.id = p.moderator_id
            ORDER BY p.submission_date DESC
        ");

        $stmt->execute();
        $papers = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    if (isset($_GET['paper_id']) && ctype_digit((string) $_GET['paper_id'])) {
        $paperId = (int) $_GET['paper_id'];

        if ($userRole === 'Lecturer') {
            $stmtDetails = $pdo->prepare("
                SELECT 
                    p.*,
                    lecturer.full_name AS lecturer_name,
                    moderator.full_name AS moderator_name,
                    (
                        SELECT hod.full_name
                        FROM users hod
                        WHERE hod.role = 'HOD'
                        AND hod.college = lecturer.college
                        ORDER BY hod.id ASC
                        LIMIT 1
                    ) AS hod_name
                FROM papers p
                INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
                LEFT JOIN users moderator ON moderator.id = p.moderator_id
                WHERE p.id = :paper_id
                AND p.lecturer_id = :lecturer_id
                LIMIT 1
            ");

            $stmtDetails->execute([
                ':paper_id' => $paperId,
                ':lecturer_id' => $userId
            ]);
        } elseif ($userRole === 'Moderator') {
            $stmtDetails = $pdo->prepare("
                SELECT 
                    p.*,
                    lecturer.full_name AS lecturer_name,
                    moderator.full_name AS moderator_name,
                    (
                        SELECT hod.full_name
                        FROM users hod
                        WHERE hod.role = 'HOD'
                        AND hod.college = lecturer.college
                        ORDER BY hod.id ASC
                        LIMIT 1
                    ) AS hod_name
                FROM papers p
                INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
                LEFT JOIN users moderator ON moderator.id = p.moderator_id
                WHERE p.id = :paper_id
                AND p.moderator_id = :moderator_id
                AND lecturer.college = :college
                LIMIT 1
            ");

            $stmtDetails->execute([
                ':paper_id' => $paperId,
                ':moderator_id' => $userId,
                ':college' => $userCollege
            ]);
        } elseif ($userRole === 'HOD') {
            $stmtDetails = $pdo->prepare("
                SELECT 
                    p.*,
                    lecturer.full_name AS lecturer_name,
                    moderator.full_name AS moderator_name,
                    (
                        SELECT hod.full_name
                        FROM users hod
                        WHERE hod.role = 'HOD'
                        AND hod.college = lecturer.college
                        ORDER BY hod.id ASC
                        LIMIT 1
                    ) AS hod_name
                FROM papers p
                INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
                LEFT JOIN users moderator ON moderator.id = p.moderator_id
                WHERE p.id = :paper_id
                AND lecturer.college = :college
                LIMIT 1
            ");

            $stmtDetails->execute([
                ':paper_id' => $paperId,
                ':college' => $userCollege
            ]);
        } elseif ($userRole === 'Admin') {
            $stmtDetails = $pdo->prepare("
                SELECT 
                    p.*,
                    lecturer.full_name AS lecturer_name,
                    moderator.full_name AS moderator_name,
                    (
                        SELECT hod.full_name
                        FROM users hod
                        WHERE hod.role = 'HOD'
                        AND hod.college = lecturer.college
                        ORDER BY hod.id ASC
                        LIMIT 1
                    ) AS hod_name
                FROM papers p
                INNER JOIN users lecturer ON lecturer.id = p.lecturer_id
                LEFT JOIN users moderator ON moderator.id = p.moderator_id
                WHERE p.id = :paper_id
                LIMIT 1
            ");

            $stmtDetails->execute([
                ':paper_id' => $paperId
            ]);
        }

        $paperDetails = $stmtDetails->fetch(PDO::FETCH_ASSOC) ?: null;

        if ($paperDetails) {
            $stmtActions = $pdo->prepare("
                SELECT
                    pa.actor_role,
                    pa.action,
                    pa.feedback,
                    pa.created_at
                FROM paper_actions pa
                WHERE pa.paper_id = :paper_id
                ORDER BY pa.created_at ASC, pa.id ASC
            ");

            $stmtActions->execute([
                ':paper_id' => $paperId
            ]);

            $paperActions = $stmtActions->fetchAll(PDO::FETCH_ASSOC);
        }
    }
} catch (PDOException $e) {
    $errorMessage = 'Failed to load progress data.';
}

function getStatusClass(string $status): string
{
    return strtolower(str_replace([' ', '/'], ['-', '-'], $status));
}

function getDisplayStatus(string $status): string
{
    return match ($status) {
        'Pending HOD Review' => 'Pending HOD Review',
        'Rejected by Moderator' => 'Rejected by Moderator',
        'Rejected by HOD' => 'Rejected by HOD',
        'Approved' => 'Approved',
        'Printed' => 'Printed',
        default => 'Pending Moderator Review',
    };
}

function getDisplayIcon(string $status): string
{
    return match ($status) {
        'Approved' => '<i class="fa-solid fa-circle-check" style="color:#4caf50;"></i>',
        'Rejected by Moderator', 'Rejected by HOD' => '<i class="fa-solid fa-circle-xmark" style="color:#f44336;"></i>',
        'Printed' => '<i class="fa-solid fa-print" style="color:#1565c0;"></i>',
        'Pending HOD Review' => '<i class="fa-regular fa-clock" style="color:#db8b00;"></i>',
        default => '<i class="fa-regular fa-clock" style="color:#db8b00;"></i>',
    };
}

function getReviewThemeClass(?string $value): string
{
    $value = strtolower(trim((string) ($value ?? '')));

    if ($value === 'submitted' || str_contains($value, 'approved')) {
        return 'review-green';
    }

    if (str_contains($value, 'rejected')) {
        return 'review-red';
    }

    if (str_contains($value, 'printed')) {
        return 'review-blue';
    }

    return 'review-yellow';
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Paper Progress Tracking - SEPMS</title>
    <link rel="stylesheet" href="assets/css/progressL.css">
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
                </div>
            </div>
        </div>
    </div>

    <div class="paper-list-container">
        <div class="container">
            <div class="paper-card">
                <h3>Paper Progress Tracking</h3>

                <?php if ($errorMessage !== ''): ?>
                    <p style="color:red;"><?= e($errorMessage) ?></p>
                <?php endif; ?>

                <?php if (empty($papers)): ?>
                    <p>No papers found.</p>
                <?php else: ?>
                    <?php foreach ($papers as $paper): ?>
                        <div class="paper-card2">
                            <div>
                                <h1><?= e($paper['paper_name'] ?? '') ?></h1>

                                <div class="paper-info-grid">
                                    <div>
                                        <p>Lecturer: <strong><?= e($paper['lecturer_name'] ?? 'N/A') ?></strong></p>

                                        <p>Submitted:
                                            <strong>
                                                <?= !empty($paper['submission_date']) ? date("M d, Y", strtotime((string) $paper['submission_date'])) : 'N/A' ?>
                                            </strong>
                                        </p>
                                    </div>

                                    <div>
                                        <p>Moderator: <strong><?= e($paper['moderator_name'] ?? 'Not assigned') ?></strong></p>

                                        <p>HOD: <strong><?= e($paper['hod_name'] ?? 'Not assigned') ?></strong></p>
                                    </div>
                                </div>
                            </div>

                            <div class="paper-card3">
                                <div class="status <?= e(getStatusClass((string) ($paper['status'] ?? ''))) ?>">
                                    <?= getDisplayIcon((string) ($paper['status'] ?? '')) ?>
                                    <?= e(getDisplayStatus((string) ($paper['status'] ?? ''))) ?>
                                </div>

                                <button class="btn-view-details"
                                    onclick="window.location.href='progress.php?paper_id=<?= (int) ($paper['id'] ?? 0) ?>'">
                                    View Details
                                </button>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php if ($paperDetails): ?>
        <div id="detailsModal" class="modal" style="display:block;">
            <div class="modal-content">
                <span class="close-btn" onclick="closeDetailsModal()">&times;</span>
                <h3 id="modal-paper-name"><?= e($paperDetails['paper_name'] ?? '') ?></h3>

                <div class="modal-content1">
                    <div class="modal-content2">
                        <p>
                            Submitted By: <br>
                            <strong id="modal-submitted-by"><?= e($paperDetails['lecturer_name'] ?? 'N/A') ?></strong>
                        </p>

                        <p>
                            Submission Date: <br>
                            <strong id="modal-submission-date">
                                <?= !empty($paperDetails['submission_date']) ? date("M d, Y H:i", strtotime((string) $paperDetails['submission_date'])) : 'N/A' ?>
                            </strong>
                        </p>
                    </div>

                    <div class="modal-content2">
                        <p>
                            Moderator: <br>
                            <strong id="modal-moderator-name"><?= e($paperDetails['moderator_name'] ?? 'Not assigned') ?></strong>
                        </p>

                        <p>
                            HOD: <br>
                            <strong id="modal-hod-name"><?= e($paperDetails['hod_name'] ?? 'Not assigned') ?></strong>
                        </p>
                    </div>


                    <p>
                        Description: <br>
                        <strong id="modal-description"><?= e($paperDetails['paper_description'] ?? '') ?></strong>
                    </p>

                    <p>
                        Current Status: <br>
                        <span style="margin-top: 8px;" class="status <?= e(getStatusClass((string) ($paperDetails['status'] ?? 'Pending'))) ?>">
                            <?= e($paperDetails['status'] ?? 'Pending') ?>
                        </span>

                    </p>

                </div>

                <div class="review-progress">
                    <h4>Review Progress</h4>
                    <ul id="review-list">

                        <?php if (!empty($paperActions)): ?>
                            <?php foreach ($paperActions as $action): ?>
                                <li class="review-item <?= e(getReviewThemeClass((string) ($action['action'] ?? ''))) ?>">
                                    <div class="stat-icon">
                                        <i class="fa-regular fa-circle-user"></i>
                                    </div>
                                    <div>
                                        <strong><?= e($action['actor_role'] ?? 'Reviewer') ?> -
                                            <?= e($action['action'] ?? '') ?></strong><br>
                                        <div style="margin:5px 0;">
                                            <i class="fa-regular fa-calendar" style="color: #3f3f3f; font-size: 15px;"></i>
                                            <span class="date">
                                                <?= !empty($action['created_at']) ? date("M d, Y H:i", strtotime((string) $action['created_at'])) : 'N/A' ?>
                                            </span>
                                        </div>
                                        <?php if (!empty($action['feedback'])): ?>
                                            <div>
                                                Feedback: <?= e($action['feedback']) ?>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </li>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <li class="review-item review-yellow">
                                <div class="stat-icon">
                                    <i class="fa-regular fa-clock"></i>
                                </div>
                                <div>
                                    <strong>Review</strong><br>
                                    <span class="status">No review actions yet</span>
                                </div>
                            </li>
                        <?php endif; ?>
                    </ul>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <script>
        function closeDetailsModal() {
            window.location.href = 'progress.php';
        }

        window.onclick = function(event) {
            const modal = document.getElementById('detailsModal');
            if (modal && event.target === modal) {
                closeDetailsModal();
            }
        }
    </script>
</body>

</html>