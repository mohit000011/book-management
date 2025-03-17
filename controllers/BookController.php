<?php
header("Content-Type: application/json"); // Ensure JSON response

require dirname(__DIR__) . '/includes/db.php';
 // Database connection
require dirname(__DIR__) . '/middleware/auth.php'; // Token validation
require dirname(__DIR__) . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . "/../");
$dotenv->load();

// Check if JWT_SECRET exists
if (!isset($_ENV['JWT_SECRET']) || empty($_ENV['JWT_SECRET'])) {
    http_response_code(500);
    echo json_encode(["error" => "Server configuration error: Missing JWT secret"]);
    exit;
}

$key = $_ENV['JWT_SECRET']; // Load secret key from .env

$method = $_SERVER['REQUEST_METHOD']; // Get HTTP method

// Fetch all books
if ($method == 'GET' && isset($_GET['action']) && $_GET['action'] == 'view') {
    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 5; // Default 5 books per page
    $offset = ($page - 1) * $limit;

    // Get total book count
    $totalStmt = $conn->query("SELECT COUNT(*) AS total FROM books");
    $totalBooks = $totalStmt->fetch(PDO::FETCH_ASSOC)['total'];
    $totalPages = ceil($totalBooks / $limit);

    // Fetch paginated books
    $stmt = $conn->prepare("SELECT * FROM books LIMIT :limit OFFSET :offset");
    $stmt->bindValue(":limit", $limit, PDO::PARAM_INT);
    $stmt->bindValue(":offset", $offset, PDO::PARAM_INT);
    $stmt->execute();

    $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

    http_response_code(200);
    echo json_encode([
        "current_page" => $page,
        "total_pages" => $totalPages,
        "total_books" => $totalBooks,
        "books" => $books
    ]);
    exit;
}


// Search books by title or author
if ($method == 'GET' && isset($_GET['action']) && $_GET['action'] == 'search') {
    $search = isset($_GET['query']) ? "%" . $_GET['query'] . "%" : "%";
    $stmt = $conn->prepare("SELECT * FROM books WHERE title LIKE :query OR author LIKE :query");
    $stmt->bindValue(":query", $search);
    $stmt->execute();
    
    $books = $stmt->fetchAll(PDO::FETCH_ASSOC);
    http_response_code(200);
    echo json_encode($books);
    exit;
}

// Add a new book
if ($method == 'POST' && isset($_GET['action']) && $_GET['action'] == 'add') {
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Authorization token required"]);
        exit;
    }

    $token = str_replace("Bearer ","", $headers['Authorization']);
  

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $userRole = $decoded->role ?? 'user'; // Default to 'user' if role is missing

        // Restrict Add access to Admins only
        if ($userRole !== 'admin') {
            http_response_code(403);
            echo json_encode(["error" => "Access denied. Only admins can add books."]);
            exit;
        }

        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input['title']) || empty($input['author']) || empty($input['genre']) || empty($input['published_year'])) {
            http_response_code(400);
            echo json_encode(["error" => "All fields are required"]);
            exit;
        }

        $stmt = $conn->prepare("INSERT INTO books (title, author, genre, published_year) VALUES (:title, :author, :genre, :published_year)");
        $stmt->bindValue(":title", $input['title']);
        $stmt->bindValue(":author", $input['author']);
        $stmt->bindValue(":genre", $input['genre']);
        $stmt->bindValue(":published_year", $input['published_year'], PDO::PARAM_INT);

        if ($stmt->execute()) {
            http_response_code(201);
            echo json_encode(["message" => "Book added successfully"]);
        } else {
            http_response_code(500);
            echo json_encode(["error" => "Failed to add book"]);
        }

    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
    }

    exit;
}

// Update book details
if ($method == 'PUT' && isset($_GET['action']) && $_GET['action'] == 'update') {
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Authorization token required"]);
        exit;
    }

    $token = str_replace("Bearer ", "", $headers['Authorization']);
    

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $userRole = $decoded->role ?? 'user'; // Default to 'user' if role is missing

        // Restrict update access to Admins only
        if ($userRole !== 'admin') {
            http_response_code(403);
            echo json_encode(["error" => "Access denied. Only admins can update books."]);
            exit;
        }

        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input['id']) || empty($input['title']) || empty($input['author']) || empty($input['genre']) || empty($input['published_year'])) {
            http_response_code(400);
            echo json_encode(["error" => "All fields are required"]);
            exit;
        }

        $stmt = $conn->prepare("UPDATE books SET title=:title, author=:author, genre=:genre, published_year=:published_year WHERE id=:id");
        $stmt->bindValue(":title", $input['title']);
        $stmt->bindValue(":author", $input['author']);
        $stmt->bindValue(":genre", $input['genre']);
        $stmt->bindValue(":published_year", $input['published_year'], PDO::PARAM_INT);
        $stmt->bindValue(":id", $input['id'], PDO::PARAM_INT);

        if ($stmt->execute()) {
            http_response_code(200);
            echo json_encode(["message" => "Book updated successfully"]);
        } else {
            http_response_code(500);
            echo json_encode(["error" => "Failed to update book"]);
        }

    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
    }

    exit;
}


// Delete book (Admin Only)
if ($method == 'DELETE' && isset($_GET['action']) && $_GET['action'] == 'delete') {
    // Authenticate user and get their role
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(["error" => "Authorization token required"]);
        exit;
    }

    $token = str_replace("Bearer ", "", $headers['Authorization']);

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $userRole = $decoded->role ?? 'user'; // Default to 'user' if role is missing

        // Restrict delete access to Admins only
        if ($userRole !== 'admin') {
            http_response_code(403);
            echo json_encode(["error" => "Access denied. Only admins can delete books."]);
            exit;
        }

        // Read Input
        $input = json_decode(file_get_contents("php://input"), true);
        if (!isset($input['id']) || empty($input['id'])) {
            http_response_code(400);
            echo json_encode(["error" => "Book ID is required"]);
            exit;
        }

        // Check if book exists
        $stmt = $conn->prepare("SELECT * FROM books WHERE id = :id");
        $stmt->bindValue(":id", $input['id'], PDO::PARAM_INT);
        $stmt->execute();
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            http_response_code(404);
            echo json_encode(["error" => "Book not found"]);
            exit;
        }

        // Delete the book
        $stmt = $conn->prepare("DELETE FROM books WHERE id=:id");
        $stmt->bindValue(":id", $input['id'], PDO::PARAM_INT);

        if ($stmt->execute()) {
            http_response_code(200);
            echo json_encode(["message" => "Book deleted successfully"]);
        } else {
            http_response_code(500);
            echo json_encode(["error" => "Failed to delete book"]);
        }

    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(["error" => "Invalid token"]);
    }

    exit;
}




// **Invalid request**
http_response_code(400);
echo json_encode(["error" => "Invalid request"]);
exit;
