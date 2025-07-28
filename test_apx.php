<?php
require_once 'apx.php';

// Configuration for Apx
$config = [
    'database' => [
        'dsn' => 'sqlite:' . __DIR__ . '/database_apx.db',
        'username' => null,
        'password' => null
    ],
    'app' => [
        'name' => 'test_app',
        'secret' => bin2hex(random_bytes(32)),
        'db_type' => 'sql'
    ]
];

// Save configuration to config.php
file_put_contents(__DIR__ . '/config.php', '<?php return ' . var_export($config, true) . ';');

// Initialize Apx Framework
$app = new Apx\Apx(__DIR__ . '/config.php');

// Define custom routes for user CRUD operations
Apx\Router::get('/api/users', function($params, $data) use ($app) {
    $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $userManager = new Apx\UserManager('sql');
    if ($user = $userManager->validateToken($token)) {
        $users = Apx\BlackBean::findAll('user');
        $result = [];
        foreach ($users as $u) {
            $role = Apx\BlackBean::load('role', $u->role_id);
            $result[] = [
                'id' => $u->id,
                'username' => $u->username,
                'email' => $u->email,
                'role' => ['name' => $role ? $role->name : 'N/A']
            ];
        }
        return $result;
    }
    http_response_code(401);
    return ['error' => 'Unauthorized'];
});

Apx\Router::post('/api/users', function($params, $data) use ($app) {
    $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $userManager = new Apx\UserManager('sql');
    if ($userManager->validateToken($token)) {
        try {
            $user = $userManager->createUser(
                $data['username'] ?? '',
                $data['password'] ?? '',
                $data['email'] ?? '',
                $data['role'] ?? 'user'
            );
            return ['id' => $user->id, 'username' => $user->username, 'email' => $user->email];
        } catch (Exception $e) {
            http_response_code(400);
            return ['error' => $e->getMessage()];
        }
    }
    http_response_code(401);
    return ['error' => 'Unauthorized'];
});

Apx\Router::put('/api/users/:id', function($params, $data) use ($app) {
    $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $userManager = new Apx\UserManager('sql');
    if ($userManager->validateToken($token)) {
        $user = Apx\BlackBean::load('user', $params['id']);
        if ($user) {
            $user->username = $data['username'] ?? $user->username;
            $user->email = $data['email'] ?? $user->email;
            if (isset($data['password']) && $data['password']) {
                $user->password = password_hash($data['password'], PASSWORD_BCRYPT);
            }
            $user->save();
            return ['id' => $user->id, 'username' => $user->username, 'email' => $user->email];
        }
        http_response_code(404);
        return ['error' => 'User not found'];
    }
    http_response_code(401);
    return ['error' => 'Unauthorized'];
});

Apx\Router::delete('/api/users/:id', function($params, $data) use ($app) {
    $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $userManager = new Apx\UserManager('sql');
    if ($userManager->validateToken($token)) {
        if ($userManager->deleteUser($params['id'])) {
            return ['success' => true];
        }
        http_response_code(404);
        return ['error' => 'User not found'];
    }
    http_response_code(401);
    return ['error' => 'Unauthorized'];
});

// Run the application
$app->run();
?>