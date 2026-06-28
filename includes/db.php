<?php
declare(strict_types=1);

// Set database connection details using environment variables or fallback to defaults
define('DB_HOST', getenv('DB_HOST') ?: 'localhost');  // Default to 'localhost' if DB_HOST is not set
define('DB_NAME', getenv('DB_NAME') ?: 'sepms');      // Default to 'sepms' if DB_NAME is not set
define('DB_USER', getenv('DB_USER') ?: 'root');       // Default to 'root' if DB_USER is not set
define('DB_PASS', getenv('DB_PASS') ?: '');           // Default to empty password if DB_PASS is not set

/**
 * Returns a PDO connection to the database.
 *
 * This function creates and returns a singleton PDO instance to be used throughout the application.
 * If the PDO connection already exists, it will be reused.
 *
 * @return PDO The PDO instance.
 * @throws PDOException If the connection fails.
 */
function db(): PDO {
    static $pdo = null;

    // If the PDO connection already exists, return it
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    try {
        // Create the Data Source Name (DSN) for the database connection
        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
        
        // Create a new PDO instance with the provided connection details
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,  // Enable exceptions for errors
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,  // Return data as associative arrays
            PDO::ATTR_EMULATE_PREPARES => false, // Disable emulation of prepared statements for security
        ]);
    } catch (PDOException $e) {
        // Log the error with the file and line where it occurred for better traceability
        error_log("Database connection failed in " . __FILE__ . " on line " . __LINE__ . ": " . $e->getMessage());
        
        // Show a user-friendly message to avoid exposing sensitive details to the end-user
        die("Database connection failed. Please try again later.");
    }

    return $pdo;
}
?>