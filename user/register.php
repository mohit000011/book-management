<?php
header("Content-Type: application/json"); // Ensure JSON response

require dirname(__DIR__) . '/includes/db.php'; // Database connection
require dirname(__DIR__) . '/vendor/autoload.php'; // Load dependencies

// Check if request method is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit;
}

// Get input JSON and validate
$rawInput = file_get_contents("php://input");
$input = json_decode($rawInput, true);

// Check if JSON decoding was successful
if (!is_array($input)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid JSON format"]);
    exit;
}

// Validate required fields
$required_fields = ['username', 'email', 'password', 'role'];
foreach ($required_fields as $field) {
    if (empty($input[$field])) {
        http_response_code(400);
        echo json_encode(["error" => "Field '$field' is required"]);
        exit;
    }
}

// Ensure role is valid (Only 'admin' or 'user')
$valid_roles = ['admin', 'user'];
if (!in_array($input['role'], $valid_roles)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid role. Use 'admin' or 'user'"]);
    exit;
}

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = :email");
$stmt->bindValue(":email", $input['email']);
$stmt->execute();

if ($stmt->fetch()) {
    http_response_code(409);
    echo json_encode(["error" => "Email already registered"]);
    exit;
}

// Hash the password
$hashed_password = password_hash($input['password'], PASSWORD_BCRYPT);

// Insert new user
$stmt = $conn->prepare("INSERT INTO users (username, email, password, role) VALUES (:username, :email, :password, :role)");
$stmt->bindValue(":username", $input['username']);
$stmt->bindValue(":email", $input['email']);
$stmt->bindValue(":password", $hashed_password);
$stmt->bindValue(":role", $input['role']);

if ($stmt->execute()) {
    http_response_code(201);
    echo json_encode(["message" => "User registered successfully"]);
} else {
    http_response_code(500);
    echo json_encode(["error" => "Failed to register user"]);
}
exit;
?>
