<?php
session_start();

// Include database connection
require_once '../includes/db.php';

// Only Admin can access audit logs
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Admin') {
    header('Location: ../index.php?error=unauthorized');
    exit;
}

$selected_role = $_GET['role'] ?? 'all-roles';
$selected_action = $_GET['action'] ?? 'all-actions';

// --- Fetch all logs ---
$pdo = db();
$query = "SELECT al.*, u.full_name, u.role, p.paper_name 
          FROM action_logs al
          JOIN users u ON al.user_id = u.id 
          LEFT JOIN papers p ON al.paper_id = p.id
          WHERE 1";

// Apply filters for role and action
if ($selected_role != 'all-roles') {
    $query .= " AND LOWER(u.role) = LOWER(:role)";
}
if ($selected_action != 'all-actions') {
    $query .= " AND LOWER(al.action_type) = LOWER(:action)";
}

// Order by timestamp descending
$query .= " ORDER BY al.created_at DESC";

$stmt = $pdo->prepare($query);
if ($selected_role != 'all-roles') {
    $stmt->bindParam(':role', $selected_role, PDO::PARAM_STR);
}
if ($selected_action != 'all-actions') {
    $stmt->bindParam(':action', $selected_action, PDO::PARAM_STR);
}
$stmt->execute();
$audit_logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Logs - SEPMS</title>
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

    <!-- Audit Logs Content -->
    <div class="container" style="margin: 20px auto;">
        <div class="exam-papers-table">
            <h3>Audit Logs</h3>

            <!-- Search and Filter Bar -->
            <div class="audit-logs-search">
                <input type="text" id="search-bar" placeholder="Search logs..." class="search-logs">
                <select id="role-filter" class="role-filter" onchange="filterLogs()">
                    <option value="all-roles" <?= ($selected_role == 'all-roles') ? 'selected' : ''; ?>>All Roles</option>
                    <option value="lecturer" <?= ($selected_role == 'lecturer') ? 'selected' : ''; ?>>Lecturer</option>
                    <option value="moderator" <?= ($selected_role == 'moderator') ? 'selected' : ''; ?>>Moderator</option>
                    <option value="hod" <?= ($selected_role == 'hod') ? 'selected' : ''; ?>>HOD</option>
                    <option value="admin" <?= ($selected_role == 'admin') ? 'selected' : ''; ?>>Admin</option>
                </select>
                <select id="action-filter" class="action-filter" onchange="filterLogs()">
                    <option value="all-actions" <?= ($selected_action == 'all-actions') ? 'selected' : ''; ?>>All Actions</option>
                    <option value="login" <?= ($selected_action == 'login') ? 'selected' : ''; ?>>Login</option>
                    <option value="logout" <?= ($selected_action == 'logout') ? 'selected' : ''; ?>>Logout</option>
                    <option value="register" <?= ($selected_action == 'register') ? 'selected' : ''; ?>>Register</option>
                    <option value="submitted" <?= ($selected_action == 'submitted') ? 'selected' : ''; ?>>Submitted</option>
                    <option value="resubmitted" <?= ($selected_action == 'resubmitted') ? 'selected' : ''; ?>>Resubmitted</option>
                    <option value="approve" <?= ($selected_action == 'approve') ? 'selected' : ''; ?>>Approve</option>
                    <option value="reject" <?= ($selected_action == 'reject') ? 'selected' : ''; ?>>Reject</option>
                    <option value="approve registration" <?= ($selected_action == 'approve registration') ? 'selected' : ''; ?>>Approve Registration</option>
                    <option value="delete user" <?= ($selected_action == 'delete user') ? 'selected' : ''; ?>>Delete User</option>
                    <option value="update user status" <?= ($selected_action == 'update user status') ? 'selected' : ''; ?>>Update User Status</option>
                    <option value="add subject" <?= ($selected_action == 'add subject') ? 'selected' : ''; ?>>Add Subject</option>
                </select>
            </div>

            <!-- Audit Logs Table -->
            <table class="user-table" id="audit-log-table">
                <thead>
                    <tr>
                        <th>No.</th>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Role</th>
                        <th>Actions</th>
                        <th>Paper Name</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    <?php $row_number = 1; ?>
                    <?php foreach ($audit_logs as $log): ?>
                        <tr>
                            <td><?= $row_number++; ?></td>
                            <td><?= date("M d, Y H:i:s", strtotime($log['created_at'])); ?></td>
                            <td><?= htmlspecialchars($log['full_name']); ?></td>
                            <td><span class="role <?= strtolower($log['role']); ?>"><?= strtoupper($log['role']); ?></span></td>
                            <td><?= ucfirst($log['action_type']); ?></td>
                            <td>
                                <?= in_array($log['action_type'], [
                                    'Login',
                                    'Logout',
                                    'Register',
                                    'Approve Registration',
                                    'Delete User',
                                    'Add Subject',
                                    'Update User Status'
                                ]) ? '-' : htmlspecialchars($log['paper_name']); ?>
                            </td>
                            <td><?= htmlspecialchars($log['description']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Back to Top Button -->
    <button id="back-to-top" title="Go to top">↑</button>

    <script>
        // Search bar function with renumbering
        document.getElementById("search-bar").addEventListener("keyup", function() {
            const searchValue = this.value.toLowerCase();
            const rows = document.querySelectorAll("#audit-log-table tbody tr");
            let visibleCount = 1;

            rows.forEach(row => {
                const timestamp = row.cells[1].textContent.toLowerCase();
                const user = row.cells[2].textContent.toLowerCase();
                const role = row.cells[3].textContent.toLowerCase();
                const action = row.cells[4].textContent.toLowerCase();
                const paper = row.cells[5].textContent.toLowerCase();
                const details = row.cells[6].textContent.toLowerCase();

                if (timestamp.includes(searchValue) || user.includes(searchValue) || role.includes(searchValue) || action.includes(searchValue) || paper.includes(searchValue) || details.includes(searchValue)) {
                    row.style.display = "";
                    row.cells[0].textContent = visibleCount++;
                } else {
                    row.style.display = "none";
                }
            });
        });

        // Function to filter logs based on selected role or action
        function filterLogs() {
            const selectedRole = document.getElementById("role-filter").value;
            const selectedAction = document.getElementById("action-filter").value;
            window.location.href = `?role=${selectedRole}&action=${selectedAction}`;
        }

        // Back to Top Button functionality
        const backToTopButton = document.getElementById("back-to-top");
        window.onscroll = function() {
            if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) {
                backToTopButton.style.display = "block";
            } else {
                backToTopButton.style.display = "none";
            }
        };
        backToTopButton.addEventListener("click", function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    </script>
</body>

</html>