<?php

declare(strict_types=1);
session_start();

require_once 'includes/db.php';

if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'Admin') {
    header('Location: index.php?error=unauthorized');
    exit;
}

$paper_id = isset($_GET['paper_id']) && ctype_digit((string) $_GET['paper_id'])
    ? (int) $_GET['paper_id']
    : 0;

if ($paper_id <= 0) {
    header('Location: dashboard.php?error=invalid_paper');
    exit;
}

$pdo = db();

$stmt = $pdo->prepare("
    SELECT 
        p.*,
        lecturer.full_name AS lecturer_name,
        moderator.full_name AS moderator_name,
        hod.full_name AS hod_name
    FROM papers p
    JOIN users lecturer ON lecturer.id = p.lecturer_id
    LEFT JOIN users moderator ON moderator.id = p.moderator_id
    LEFT JOIN users hod ON hod.id = p.hod_id
    WHERE p.id = :paper_id
      AND p.status = 'Approved'
    LIMIT 1
");

$stmt->execute([
    ':paper_id' => $paper_id
]);

$paper = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$paper) {
    header('Location: dashboard.php?error=invalid_paper');
    exit;
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

$paperName = $paper['paper_name'] ?? $paper['title'] ?? 'Approved Paper';
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Print Paper - <?= e((string) $paperName) ?></title>

    <style>
        body {
            margin: 0;
            background: #f3f4f6;
            font-family: Arial, sans-serif;
        }

        .top-bar {
            padding: 14px 20px;
            background: #ffffff;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .top-bar h2 {
            margin: 0;
            font-size: 18px;
            color: #111827;
        }

        .actions {
            display: flex;
            gap: 10px;
        }

        .btn {
            border: none;
            padding: 9px 14px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
        }

        .btn-print {
            background: #2563eb;
            color: #ffffff;
        }

        .btn-back {
            background: #e5e7eb;
            color: #111827;
        }

        .paper-frame {
            width: 100%;
            height: calc(100vh - 65px);
            border: none;
            background: #ffffff;
        }

        @media print {
            .top-bar {
                display: none;
            }

            .paper-frame {
                height: 100vh;
            }

            body {
                background: #ffffff;
            }
        }
    </style>
</head>

<body>

    <div class="top-bar">
        <h2><?= e((string) $paperName) ?></h2>

        <div class="actions">
            <button class="btn btn-print" onclick="printPaper()">Print</button>
            <button class="btn btn-back" onclick="window.location.href='dashboard.php'">Back</button>
        </div>
    </div>

    <iframe
        id="paperFrame"
        class="paper-frame"
        src="admin_decrypt.php?paper_id=<?= (int) $paper_id ?>">
    </iframe>

    <script>
        function printPaper() {
            const frame = document.getElementById('paperFrame');

            frame.focus();

            try {
                frame.contentWindow.print();
            } catch (error) {
                window.print();
            }
        }

        window.addEventListener('load', function() {
            const frame = document.getElementById('paperFrame');

            frame.addEventListener('load', function() {
                setTimeout(function() {
                    printPaper();
                }, 800);
            });
        });
    </script>

</body>

</html>