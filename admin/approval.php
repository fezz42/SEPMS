<?php
session_start();

// Include database connection
require_once '../includes/db.php';

// Ensure the user is an Admin
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Admin') {
    header('Location: ../index.php?error=unauthorized');
    exit;
}

if (empty($_SESSION['csrf_approve_user'])) {
    $_SESSION['csrf_approve_user'] = bin2hex(random_bytes(32));
}

// Function to handle redirection with success or error message
function redirectWithMessage(string $url, string $messageType): void
{
    header("Location: $url?$messageType=1");
    exit;
}

// Handle user approval using POST + CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['approve_user_id'])) {
    if (
        empty($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_approve_user'], $_POST['csrf_token'])
    ) {
        redirectWithMessage('approval.php', 'invalid_csrf');
    }

    if (!is_numeric($_POST['approve_user_id'])) {
        redirectWithMessage('approval.php', 'db_error');
    }

    $user_id = (int) $_POST['approve_user_id'];
    $pdo = db();

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare("
            SELECT full_name, role 
            FROM users 
            WHERE id = :user_id 
              AND registration = 'pending'
            LIMIT 1
        ");
        $stmt->execute([':user_id' => $user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $pdo->rollBack();
            redirectWithMessage('approval.php', 'db_error');
        }

        $stmt = $pdo->prepare("
            UPDATE users 
            SET registration = 'approved' 
            WHERE id = :user_id
        ");
        $stmt->execute([':user_id' => $user_id]);

        $stmt_log = $pdo->prepare("
            INSERT INTO action_logs (user_id, action_type, description)
            VALUES (:user_id, :action_type, :description)
        ");
        $stmt_log->execute([
            ':user_id' => $_SESSION['user']['id'],
            ':action_type' => 'Approve Registration',
            ':description' => 'Admin approved registration for ' . $user['role'] . ' ' . $user['full_name']
        ]);

        $pdo->commit();

        unset($_SESSION['csrf_approve_user']);

        redirectWithMessage('approval.php', 'success');
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log("Database error: " . $e->getMessage());
        redirectWithMessage('approval.php', 'db_error');
    }
}

// Fetch users who are pending approval
$pdo = db();
$stmt = $pdo->prepare("SELECT id, full_name, username, email, role FROM users WHERE registration = 'pending'");
$stmt->execute();
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Registrations - SEPMS</title>
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

    <!-- Success or Error Message Display -->
    <div class="container" style="margin-top: 20px;">


        <!-- Pending Registrations Content -->
        <div class="exam-papers-table">
            <div>
                <?php if (isset($_GET['success'])): ?>
                    <div class="msg success">User successfully approved!</div>
                <?php elseif (isset($_GET['db_error'])): ?>
                    <div class="msg error">There was a database error. Please try again.</div>
                <?php elseif (isset($_GET['invalid_csrf'])): ?>
                    <div class="msg error">Invalid request. Please try again.</div>
                <?php endif; ?>
            </div>

            <h3>Pending Registrations</h3>

            <!-- Display message if no users are pending approval -->
            <?php if (empty($users)): ?>
                <p>No new user registration to approve.</p>
            <?php else: ?>
                <p>Review and approve new user registrations (<?php echo count($users); ?> pending)</p>

                <table class="user-table" id="user-table">
                    <thead>
                        <tr>
                            <th>Full Name</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['full_name']); ?></td>
                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                <td><?php echo htmlspecialchars($user['email']); ?></td>
                                <td><span class="role <?php echo strtolower($user['role']); ?>"><?php echo strtoupper($user['role']); ?></span></td>
                                <td>
                                    <form method="POST" action="approval.php" style="display:inline;">
                                        <input type="hidden" name="approve_user_id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_approve_user']); ?>">

                                        <button type="submit" class="btn-edit" onclick="return confirm('Are you sure you want to approve this user?');">
                                            Approve
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</body>

</html>