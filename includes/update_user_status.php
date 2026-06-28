<?php

declare(strict_types=1);

session_start();

require_once __DIR__ . '/db.php';

// Ensure the user is an admin
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Admin') {
    echo 'Unauthorized access';
    exit;
}

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo 'Invalid request method';
    exit;
}

// Check CSRF token
if (
    empty($_POST['csrf_token']) ||
    empty($_SESSION['csrf_user_action']) ||
    !hash_equals($_SESSION['csrf_user_action'], (string) $_POST['csrf_token'])
) {
    echo 'Invalid request';
    exit;
}

$pdo = db();
$admin_id = (int) $_SESSION['user']['id'];

// Handle block/unblock user status
if (isset($_POST['user_id'], $_POST['status'])) {
    $user_id = (int) $_POST['user_id'];
    $status = (string) $_POST['status'];

    if (!in_array($status, ['active', 'blocked'], true)) {
        echo 'Invalid status';
        exit;
    }

    if ($user_id === $admin_id) {
        echo 'You cannot modify your own account';
        exit;
    }

    try {
        $pdo->beginTransaction();

        $targetUser = getUserById($pdo, $user_id);

        if (!$targetUser) {
            $pdo->rollBack();
            echo 'User not found';
            exit;
        }

        if ($targetUser['role'] === 'Admin') {
            $pdo->rollBack();
            echo 'Admin accounts cannot be modified here';
            exit;
        }

        $stmt = $pdo->prepare("
            UPDATE users 
            SET status = :status 
            WHERE id = :user_id
              AND role != 'Admin'
        ");

        $stmt->execute([
            ':status' => $status,
            ':user_id' => $user_id
        ]);

        logAction(
            $pdo,
            $admin_id,
            'Update User Status',
            'Admin updated status to ' . $status . ' for ' . $targetUser['full_name']
        );

        $pdo->commit();

        echo 'User status updated successfully';
        exit;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log($e->getMessage());
        echo 'Error: Could not update user status';
        exit;
    }
}

// Handle user deletion
if (isset($_POST['delete_user_id'])) {
    $user_id = (int) $_POST['delete_user_id'];

    if ($user_id === $admin_id) {
        echo 'You cannot delete your own account';
        exit;
    }

    try {
        $pdo->beginTransaction();

        $targetUser = getUserById($pdo, $user_id);

        if (!$targetUser) {
            $pdo->rollBack();
            echo 'User not found';
            exit;
        }

        if ($targetUser['role'] === 'Admin') {
            $pdo->rollBack();
            echo 'Admin accounts cannot be deleted here';
            exit;
        }

        $stmt = $pdo->prepare("
            DELETE FROM users 
            WHERE id = :user_id
              AND role != 'Admin'
        ");

        $stmt->execute([
            ':user_id' => $user_id
        ]);

        logAction(
            $pdo,
            $admin_id,
            'Delete User',
            'Admin deleted user: ' . $targetUser['full_name']
        );

        $pdo->commit();

        echo 'User deleted successfully';
        exit;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log($e->getMessage());
        echo 'Error: Could not delete user';
        exit;
    }
}

echo 'Invalid action';
exit;

// Get user details by ID
function getUserById(PDO $pdo, int $user_id): ?array
{
    $stmt = $pdo->prepare("
        SELECT id, full_name, role, status
        FROM users 
        WHERE id = :user_id 
        LIMIT 1
    ");

    $stmt->execute([
        ':user_id' => $user_id
    ]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    return $user ?: null;
}

// Log action into action_logs table
function logAction(PDO $pdo, int $admin_id, string $action_type, string $description): void
{
    $stmt = $pdo->prepare("
        INSERT INTO action_logs (user_id, action_type, description)
        VALUES (:user_id, :action_type, :description)
    ");

    $stmt->execute([
        ':user_id' => $admin_id,
        ':action_type' => $action_type,
        ':description' => $description
    ]);
}
