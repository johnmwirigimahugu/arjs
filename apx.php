<?php
/**
 * Apx PHP Framework
 * Version: 1.0.0
 * Author: John "Kesh" Mahugu
 * Copyright: © 2025 John "Kesh" Mahugu. All rights reserved.
 * Created: 07:23 AM EAT, Saturday, July 19, 2025
 * License: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace Apx;

use PDO;
use PDOException;
use RuntimeException;
use stdClass;

// Autoloader for /arke folder
spl_autoload_register(function ($class) {
    if (strpos($class, 'Apx\\') === 0) {
        $className = str_replace('Apx\\', '', $class);
        $file = __DIR__ . '/arke/' . $className . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});

// BlackBean ORM
class BlackBean
{
    protected static $pdo;
    protected static $dsn;
    protected static $username;
    protected static $password;
    protected static $options = [];
    protected static $logger = null;
    protected $type;
    protected $props = [];
    protected $dirty = [];
    protected $exists = false;

    public static function setup($dsn, $username = null, $password = null, $options = [])
    {
        self::$dsn = $dsn;
        self::$username = $username;
        self::$password = $password;
        self::$options = $options + [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ];
        self::$pdo = new PDO($dsn, $username, $password, self::$options);
    }

    public static function pdo()
    {
        if (!self::$pdo) throw new Exception("Call BlackBean::setup() first.");
        return self::$pdo;
    }

    public static function logger($logger = null)
    {
        if ($logger !== null) self::$logger = $logger;
        return self::$logger;
    }

    public static function dispense($type)
    {
        $bean = new self();
        $bean->type = $type;
        $bean->props = [];
        $bean->exists = false;
        return $bean;
    }

    public static function load($type, $id)
    {
        $pdo = self::pdo();
        $stmt = $pdo->prepare("SELECT * FROM $type WHERE id = ?");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) return null;
        $bean = new self();
        $bean->type = $type;
        $bean->props = $row;
        $bean->exists = true;
        return $bean;
    }

    public static function find($type, $where = '', $params = [])
    {
        $pdo = self::pdo();
        $sql = "SELECT * FROM $type";
        if ($where) $sql .= " WHERE $where";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
        $beans = [];
        foreach ($rows as $row) {
            $bean = new self();
            $bean->type = $type;
            $bean->props = $row;
            $bean->exists = true;
            $beans[] = $bean;
        }
        return $beans;
    }

    public static function findOne($type, $where = '', $params = [])
    {
        $beans = self::find($type, $where, $params);
        return $beans ? $beans[0] : null;
    }

    public static function findAll($type)
    {
        return self::find($type);
    }

    public function save()
    {
        $pdo = self::pdo();
        $this->autoMigrate();
        if ($this->exists) {
            $cols = [];
            $vals = [];
            foreach ($this->props as $k => $v) {
                if ($k === 'id') continue;
                $cols[] = "$k = ?";
                $vals[] = $v;
            }
            $vals[] = $this->props['id'];
            $sql = "UPDATE {$this->type} SET " . implode(',', $cols) . " WHERE id = ?";
            $pdo->prepare($sql)->execute($vals);
        } else {
            $cols = array_keys($this->props);
            $vals = array_values($this->props);
            $placeholders = implode(',', array_fill(0, count($cols), '?'));
            $sql = "INSERT INTO {$this->type} (" . implode(',', $cols) . ") VALUES ($placeholders)";
            $pdo->prepare($sql)->execute($vals);
            $this->props['id'] = $pdo->lastInsertId();
            $this->exists = true;
        }
        return $this;
    }

    public function delete()
    {
        if (!$this->exists) return false;
        $pdo = self::pdo();
        $pdo->prepare("DELETE FROM {$this->type} WHERE id = ?")->execute([$this->props['id']]);
        $this->exists = false;
        return true;
    }

    public function __get($k)
    {
        return $this->props[$k] ?? null;
    }

    public function __set($k, $v)
    {
        $this->props[$k] = $v;
    }

    public function __isset($k)
    {
        return isset($this->props[$k]);
    }

    public function __unset($k)
    {
        unset($this->props[$k]);
    }

    protected function autoMigrate()
    {
        $pdo = self::pdo();
        $table = $this->type;
        $cols = $this->props;
        $colDefs = [];
        foreach ($cols as $k => $v) {
            if ($k === 'id') continue;
            $colDefs[] = "$k " . self::sqlType($v);
        }
        $colDefs = implode(',', $colDefs);
        $pdo->exec("CREATE TABLE IF NOT EXISTS $table (id INTEGER PRIMARY KEY AUTOINCREMENT $colDefs" . ($colDefs ? ',' : '') . ")");
        $existingCols = [];
        $q = $pdo->query("PRAGMA table_info($table)");
        if ($q) {
            foreach ($q->fetchAll(PDO::FETCH_ASSOC) as $col) {
                $existingCols[] = $col['name'];
            }
        }
        foreach ($cols as $k => $v) {
            if (!in_array($k, $existingCols)) {
                $pdo->exec("ALTER TABLE $table ADD COLUMN $k " . self::sqlType($v));
            }
        }
    }

    protected static function sqlType($v)
    {
        if (is_int($v)) return 'INTEGER';
        if (is_float($v)) return 'REAL';
        if (is_null($v)) return 'TEXT';
        if (is_string($v) && strlen($v) < 256) return 'TEXT';
        if (is_string($v)) return 'TEXT';
        return 'TEXT';
    }

    public function link($otherBean, $fk = null)
    {
        if (!$fk) $fk = $otherBean->type . '_id';
        $this->$fk = $otherBean->id;
        return $this;
    }

    public function related($type, $fk = null)
    {
        if (!$fk) $fk = $this->type . '_id';
        return self::find($type, "$fk = ?", [$this->id]);
    }

    public static function begin()
    {
        self::pdo()->beginTransaction();
    }

    public static function commit()
    {
        self::pdo()->commit();
    }

    public static function rollback()
    {
        self::pdo()->rollBack();
    }

    public static function query($sql, $params = [])
    {
        $stmt = self::pdo()->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public function export()
    {
        return $this->props;
    }
}

// SleekDB Core (Simplified)
class SleekDB
{
    private $storePath;
    private $storeName;

    public function __construct($storePath, $storeName)
    {
        $this->storePath = rtrim($storePath, '/') . '/' . $storeName;
        $this->storeName = $storeName;
        if (!is_dir($this->storePath)) {
            mkdir($this->storePath, 0755, true);
        }
    }

    public function insert($data)
    {
        $id = $this->generateId();
        $data['_id'] = $id;
        $data['created_at'] = date('Y-m-d H:i:s');
        file_put_contents("{$this->storePath}/$id.json", json_encode($data));
        return $data;
    }

    public function find($criteria = [])
    {
        $results = [];
        foreach (glob("{$this->storePath}/*.json") as $file) {
            $data = json_decode(file_get_contents($file), true);
            if ($this->matchesCriteria($data, $criteria)) {
                $results[] = $data;
            }
        }
        return $results;
    }

    public function findOne($criteria)
    {
        $results = $this->find($criteria);
        return $results ? $results[0] : null;
    }

    public function update($id, $data)
    {
        $file = "{$this->storePath}/$id.json";
        if (file_exists($file)) {
            $existing = json_decode(file_get_contents($file), true);
            $data['_id'] = $id;
            $data['created_at'] = $existing['created_at'];
            $data['updated_at'] = date('Y-m-d H:i:s');
            file_put_contents($file, json_encode($data));
            return $data;
        }
        return null;
    }

    public function delete($id)
    {
        $file = "{$this->storePath}/$id.json";
        if (file_exists($file)) {
            unlink($file);
            return true;
        }
        return false;
    }

    private function generateId()
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    private function matchesCriteria($data, $criteria)
    {
        foreach ($criteria as $key => $value) {
            if (!isset($data[$key]) || $data[$key] !== $value) {
                return false;
            }
        }
        return true;
    }
}

// FastAPI-like Router
class Router
{
    private static $routes = [];

    public static function get($path, $callback) { self::addRoute('GET', $path, $callback); }
    public static function post($path, $callback) { self::addRoute('POST', $path, $callback); }
    public static function put($path, $callback) { self::addRoute('PUT', $path, $callback); }
    public static function delete($path, $callback) { self::addRoute('DELETE', $path, $callback); }

    private static function addRoute($method, $path, $callback)
    {
        self::$routes[] = [
            'method' => $method,
            'path' => preg_replace('#:(\w+)#', '([^/]+)', $path),
            'params' => array_filter(preg_match_all('#:(\w+)#', $path, $matches) ? $matches[1] : []),
            'callback' => $callback
        ];
    }

    public static function handleRequest()
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $data = json_decode(file_get_contents('php://input'), true) ?: [];

        foreach (self::$routes as $route) {
            if ($route['method'] === $method && preg_match("#^{$route['path']}$#", $path, $matches)) {
                $params = [];
                foreach ($route['params'] as $i => $param) {
                    $params[$param] = $matches[$i + 1];
                }
                header('Content-Type: application/json');
                echo json_encode(call_user_func($route['callback'], $params, $data));
                exit;
            }
        }

        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
        exit;
    }
}

// User Management
class UserManager
{
    private $dbType;
    private $sleek;

    public function __construct($dbType = 'sql', $sleek = null)
    {
        $this->dbType = $dbType;
        $this->sleek = $sleek;
    }

    public function createUser($username, $password, $email, $roleName)
    {
        if ($this->dbType === 'nosql') {
            $user = $this->sleek->findOne(['username' => $username]);
            if ($user) {
                throw new RuntimeException('Username already exists');
            }
            $role = $this->sleek->findOne(['_type' => 'role', 'name' => $roleName]) ?:
                $this->sleek->insert(['_type' => 'role', 'name' => $roleName, 'permissions' => ['read']]);
            return $this->sleek->insert([
                '_type' => 'user',
                'username' => $username,
                'password' => password_hash($password, PASSWORD_BCRYPT),
                'email' => $email,
                'role' => $role['_id']
            ]);
        } else {
            $user = BlackBean::findOne('user', 'username = ?', [$username]);
            if ($user) {
                throw new RuntimeException('Username already exists');
            }
            $role = BlackBean::findOne('role', 'name = ?', [$roleName]);
            if (!$role) {
                $role = BlackBean::dispense('role');
                $role->name = $roleName;
                $role->permissions = json_encode(['read']);
                $role->save();
            }
            $user = BlackBean::dispense('user');
            $user->username = $username;
            $user->password = password_hash($password, PASSWORD_BCRYPT);
            $user->email = $email;
            $user->link($role, 'role_id');
            $user->created_at = date('Y-m-d H:i:s');
            $user->save();
            return $user;
        }
    }

    public function authenticate($username, $password)
    {
        if ($this->dbType === 'nosql') {
            $user = $this->sleek->findOne(['_type' => 'user', 'username' => $username]);
            if ($user && password_verify($password, $user['password'])) {
                $token = bin2hex(random_bytes(16));
                $this->sleek->insert(['_type' => 'session', 'user_id' => $user['_id'], 'token' => $token, 'expires_at' => date('Y-m-d H:i:s', strtotime('+1 hour'))]);
                return $token;
            }
        } else {
            $user = BlackBean::findOne('user', 'username = ?', [$username]);
            if ($user && password_verify($password, $user->password)) {
                $token = bin2hex(random_bytes(16));
                $session = BlackBean::dispense('session');
                $session->link($user, 'user_id');
                $session->token = $token;
                $session->expires_at = date('Y-m-d H:i:s', strtotime('+1 hour'));
                $session->save();
                return $token;
            }
        }
        return null;
    }

    public function validateToken($token)
    {
        if ($this->dbType === 'nosql') {
            $session = $this->sleek->findOne(['_type' => 'session', 'token' => $token, 'expires_at' => ['>' => date('Y-m-d H:i:s')]]);
            return $session ? $this->sleek->findOne(['_id' => $session['user_id']]) : null;
        } else {
            $session = BlackBean::findOne('session', 'token = ? AND expires_at > ?', [$token, date('Y-m-d H:i:s')]);
            return $session ? BlackBean::load('user', $session->user_id) : null;
        }
    }

    public function deleteUser($id)
    {
        if ($this->dbType === 'nosql') {
            return $this->sleek->delete($id);
        } else {
            $user = BlackBean::load('user', $id);
            if ($user) {
                $user->delete();
                return true;
            }
            return false;
        }
    }
}

// App Wizard
class AppWizard
{
    private $projectPath;
    private $storeName;
    private $dbType;
    private $config;

    public function __construct($projectPath, $storeName = 'app', $dbType = 'sql')
    {
        $this->projectPath = rtrim($projectPath, '/');
        $this->storeName = $storeName;
        $this->dbType = $dbType;
        $this->config = [
            'database' => [
                'dsn' => 'sqlite:' . $this->projectPath . '/data/database.sqlite',
                'username' => null,
                'password' => null,
            ],
            'app' => [
                'name' => $this->storeName,
                'secret' => bin2hex(random_bytes(32)),
                'db_type' => $this->dbType
            ]
        ];
    }

    public function createProject()
    {
        $dirs = [
            $this->projectPath,
            $this->projectPath . '/data',
            $this->projectPath . '/public',
            $this->projectPath . '/public/js'
        ];
        foreach ($dirs as $dir) {
            if (!is_dir($dir) && !mkdir($dir, 0755, true)) {
                throw new RuntimeException("Failed to create directory: $dir");
            }
        }

        if ($this->dbType === 'sql') {
            BlackBean::setup($this->config['database']['dsn']);
            $role = BlackBean::dispense('role');
            $role->name = 'admin';
            $role->permissions = json_encode(['create', 'read', 'update', 'delete']);
            $role->save();
            $user = BlackBean::dispense('user');
            $user->username = 'admin';
            $user->password = password_hash('admin123', PASSWORD_BCRYPT);
            $user->email = 'admin@example.com';
            $user->link($role, 'role_id');
            $user->save();
        } else {
            $sleek = new SleekDB($this->projectPath . '/data', $this->storeName);
            $role = $sleek->insert(['_type' => 'role', 'name' => 'admin', 'permissions' => ['create', 'read', 'update', 'delete']]);
            $sleek->insert(['_type' => 'user', 'username' => 'admin', 'password' => password_hash('admin123', PASSWORD_BCRYPT), 'email' => 'admin@example.com', 'role' => $role['_id']]);
        }

        $indexHtml = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{$this->storeName} Admin</title>
    <script src="https://unpkg.com/mojajs@latest/dist/moja.min.js"></script>
    <script src="/js/app.js"></script>
    <style>
        #webcli { margin-top: 20px; }
        #webcli-input { width: 100%; padding: 10px; }
        #webcli-output { border: 1px solid #ccc; padding: 10px; min-height: 100px; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div id="app"></div>
</body>
</html>
HTML;

        $appJs = <<<JS
const app = new Moja({
    el: '#app',
    template: `
        <div>
            <h1>{$this->storeName} Admin</h1>
            <div v-if="!loggedIn">
                <input v-model="username" placeholder="Username">
                <input v-model="password" type="password" placeholder="Password">
                <button @click="login">Login</button>
            </div>
            <div v-else>
                <h2>Users</h2>
                <table>
                    <tr v-for="user in users">
                        <td>{{ user.username }}</td>
                        <td>{{ user.email }}</td>
                        <td>{{ user.role.name || user.role }}</td>
                        <td>
                            <button @click="deleteUser(user.id || user._id)">Delete</button>
                        </td>
                    </tr>
                </table>
                <button @click="logout">Logout</button>
                <div id="webcli">
                    <h2>WebCLI</h2>
                    <input v-model="command" @keyup.enter="runCommand" placeholder="Enter command (e.g., create_project ./my_project my_app sql)">
                    <div id="webcli-output">{{ output }}</div>
                </div>
            </div>
        </div>
    `,
    data: {
        loggedIn: false,
        username: '',
        password: '',
        users: [],
        command: '',
        output: ''
    },
    methods: {
        async login() {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': '{$this->config['app']['secret']}' },
                body: JSON.stringify({ username: this.username, password: this.password })
            });
            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('token', data.token);
                this.loggedIn = true;
                this.fetchUsers();
            }
        },
        async fetchUsers() {
            const response = await fetch('/api/users', {
                headers: { 'Authorization': localStorage.getItem('token') }
            });
            this.users = await response.json();
        },
        async deleteUser(id) {
            await fetch(`/api/users/\${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': localStorage.getItem('token'), 'X-CSRF-Token': '{$this->config['app']['secret']}' }
            });
            this.fetchUsers();
        },
        async logout() {
            await fetch('/api/logout', {
                method: 'POST',
                headers: { 'Authorization': localStorage.getItem('token'), 'X-CSRF-Token': '{$this->config['app']['secret']}' }
            });
            this.loggedIn = false;
            this.users = [];
            localStorage.removeItem('token');
        },
        async runCommand() {
            const response = await fetch('/api/webcli', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json', 
                    'Authorization': localStorage.getItem('token'),
                    'X-CSRF-Token': '{$this->config['app']['secret']}'
                },
                body: JSON.stringify({ command: this.command })
            });
            const result = await response.json();
            this.output = JSON.stringify(result, null, 2);
            this.command = '';
        }
    }
});
JS;

        file_put_contents($this->projectPath . '/public/index.html', $indexHtml);
        file_put_contents($this->projectPath . '/public/js/app.js', $appJs);
        file_put_contents($this->projectPath . '/config.php', '<?php return ' . var_export($this->config, true) . ';');
    }
}

// Main Framework Class
class Apx
{
    private $config;
    private $sleek;
    private $userManager;

    public function __construct($configFile = null)
    {
        $this->config = $configFile ? require $configFile : [
            'database' => ['dsn' => 'sqlite:' . __DIR__ . '/data/database.sqlite', 'username' => null, 'password' => null],
            'app' => ['name' => 'app', 'secret' => bin2hex(random_bytes(32)), 'db_type' => 'sql']
        ];
        if ($this->config['app']['db_type'] === 'nosql') {
            $this->sleek = new SleekDB(__DIR__ . '/data', $this->config['app']['name']);
            $this->userManager = new UserManager('nosql', $this->sleek);
        } else {
            BlackBean::setup($this->config['database']['dsn'], $this->config['database']['username'], $this->config['database']['password']);
            $this->userManager = new UserManager('sql');
        }

        $this->setupRoutes();
    }

    private function setupRoutes()
    {
        Router::post('/api/login', function($params, $data) {
            $token = $this->userManager->authenticate($data['username'], $data['password']);
            if ($token) {
                return ['token' => $token];
            }
            http_response_code(401);
            return ['error' => 'Invalid credentials'];
        });

        Router::get('/api/users', function($params, $data) {
            $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if ($user = $this->userManager->validateToken($token)) {
                $users = $this->config['app']['db_type'] === 'nosql'
                    ? $this->sleek->find(['_type' => 'user'])
                    : BlackBean::find('user');
                $result = [];
                foreach ($users as $u) {
                    $role = $this->config['app']['db_type'] === 'nosql'
                        ? $this->sleek->findOne(['_id' => $u['role']])
                        : BlackBean::load('role', $u->role_id);
                    $result[] = [
                        'id' => $u['_id'] ?? $u->id,
                        'username' => $u['username'] ?? $u->username,
                        'email' => $u['email'] ?? $u->email,
                        'role' => ['name' => $role['name'] ?? $role->name]
                    ];
                }
                return $result;
            }
            http_response_code(401);
            return ['error' => 'Unauthorized'];
        });

        Router::delete('/api/users/:id', function($params, $data) {
            $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if ($this->userManager->validateToken($token)) {
                if ($this->userManager->deleteUser($params['id'])) {
                    return ['success' => true];
                }
                http_response_code(404);
                return ['error' => 'User not found'];
            }
            http_response_code(401);
            return ['error' => 'Unauthorized'];
        });

        Router::post('/api/logout', function($params, $data) {
            $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if ($this->config['app']['db_type'] === 'nosql') {
                $session = $this->sleek->findOne(['_type' => 'session', 'token' => $token]);
                if ($session) {
                    $this->sleek->delete($session['_id']);
                    return ['success' => true];
                }
            } else {
                $session = BlackBean::findOne('session', 'token = ?', [$token]);
                if ($session) {
                    $session->delete();
                    return ['success' => true];
                }
            }
            http_response_code(401);
            return ['error' => 'Invalid session'];
        });

        Router::post('/api/webcli', function($params, $data) {
            $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if (!$this->userManager->validateToken($token)) {
                http_response_code(401);
                return ['error' => 'Unauthorized'];
            }
            $command = $data['command'] ?? '';
            $parts = explode(' ', trim($command));
            $cmd = array_shift($parts);

            try {
                switch ($cmd) {
                    case 'create_project':
                        if (count($parts) !== 3) {
                            return ['error' => 'Usage: create_project <path> <name> <sql|nosql>'];
                        }
                        $this->createProject($parts[0], $parts[1], $parts[2]);
                        return ['output' => "Project created at {$parts[0]} with name {$parts[1]} ({$parts[2]})"];
                    case 'create_user':
                        if (count($parts) !== 4) {
                            return ['error' => 'Usage: create_user <username> <password> <email> <role>'];
                        }
                        $user = $this->userManager->createUser($parts[0], $parts[1], $parts[2], $parts[3]);
                        return ['output' => 'User created', 'data' => $this->config['app']['db_type'] === 'nosql' ? $user : $user->export()];
                    case 'test':
                        ob_start();
                        require __DIR__ . '/test_Apx.php';
                        $output = ob_get_clean();
                        return ['output' => $output];
                    case 'extension':
                        if (count($parts) !== 1) {
                            return ['error' => 'Usage: extension <name>'];
                        }
                        $arkeDir = __DIR__ . '/arke';
                        if (!is_dir($arkeDir)) {
                            mkdir($arkeDir, 0755, true);
                        }
                        $className = ucfirst($parts[0]);
                        $content = <<<PHP
<?php
namespace Apx;
class $className {
    public function test() {
        return "Extension $className loaded";
    }
}
PHP;
                        file_put_contents("$arkeDir/$className.php", $content);
                        return ['output' => "Extension $className created in /arke"];
                    default:
                        return ['error' => 'Unknown command. Available: create_project, create_user, test, extension'];
                }
            } catch (Exception $e) {
                return ['error' => $e->getMessage()];
            }
        });
    }

    public function run()
    {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if ($_SERVER['REQUEST_METHOD'] !== 'GET' && !hash_equals(hash_hmac('sha256', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), $this->config['app']['secret']), $csrfToken)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid CSRF token']);
            exit;
        }
        Router::handleRequest();
    }

    public function createProject($projectPath, $storeName = 'app', $dbType = 'sql')
    {
        $wizard = new AppWizard($projectPath, $storeName, $dbType);
        $wizard->createProject();
    }
}

// Framework Entry Point
if (basename(__FILE__) === 'Apx.php') {
    $api = new Apx(__DIR__ . '/config.php');
    $api->run();
}
?>