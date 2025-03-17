<?php
header("Content-Type: application/json"); // Ensure response is JSON

require dirname(__DIR__) . '/includes/db.php'; // Database connection
require dirname(__DIR__) . '/vendor/autoload.php'; // Load dependencies

use Firebase\JWT\JWT;
use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . "/../");
$dotenv->load();
$key = $_ENV['JWT_SECRET']; // Secret key for JWT

// Check for POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit;
}

// Get input JSON
$input = json_decode(file_get_contents("php://input"), true);
if (empty($input['email']) || empty($input['password'])) {
    http_response_code(400);
    echo json_encode(["error" => "Email and password required"]);
    exit;
}

// Check if user exists
$stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE email = :email");
$stmt->bindValue(":email", $input['email']);
$stmt->execute();
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user || !password_verify($input['password'], $user['password'])) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid credentials"]);
    exit;
}

// Generate JWT token
$payload = [
    "user_id" => $user['id'],
    "username" => $user['username'],
    "role" => $user['role'],
    "exp" => time() + (60 * 60 * 24) // Token expires in 24 hours
];

$token = JWT::encode($payload, $key, 'HS256');

// Return token
http_response_code(200);
echo json_encode([
    "message" => "Login successful",
    "token" => $token,
    "role" => $user['role']
]);
exit;
?>
