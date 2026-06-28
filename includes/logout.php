<?php
declare(strict_types=1);
session_start();

require_once __DIR__ . '/db.php';

// Log logout before destroying session
if (isset($_SESSION['user']['id'])) {
    try {
        $pdo = db();

        $stmt = $pdo->prepare("
            INSERT INTO action_logs (user_id, action_type, description)
            VALUES (:user_id, :action_type, :description)
        ");

        $stmt->execute([
            ':user_id' => (int)$_SESSION['user']['id'],
            ':action_type' => 'Logout',
            ':description' => 'User logged out successfully.'
        ]);
    } catch (PDOException $e) {
        // Ignore logging failure and continue logout
    }
}

// Clear session data
$_SESSION = [];

// Remove session cookie if it's set
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        (bool)$params['secure'],
        (bool)$params['httponly']
    );
}

// Destroy the session
session_destroy();

// Redirect to login page
header('Location: ../index.php?logout=1');
exit;