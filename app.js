(function() {
    // Application state
    let state = {
        loggedIn: false,
        username: '',
        password: '',
        users: [],
        newUser: { username: '', email: '', password: '', role: 'user' },
        command: '',
        output: '',
        csrfToken: '<?php echo $config['app']['secret']; ?>'
    };

    // DOM elements
    const app = document.querySelector('#app');

    // Render function
    function render() {
        if (!state.loggedIn) {
            app.innerHTML = `
                <div class="container">
                    <h1>Test App Admin</h1>
                    <div class="card">
                        <div class="card-body">
                            <div class="form-group">
                                <input id="username" class="input" placeholder="Username" value="${state.username}">
                            </div>
                            <div class="form-group">
                                <input id="password" type="password" class="input" placeholder="Password" value="${state.password}">
                            </div>
                            <button id="loginBtn" class="btn btn-primary">Login</button>
                        </div>
                    </div>
                </div>
            `;
            bindLoginEvents();
        } else {
            app.innerHTML = `
                <div class="container">
                    <h1>Test App Admin</h1>
                    <h2>Users</h2>
                    <div class="grid">
                        ${state.users.map(user => `
                            <div class="card">
                                <div class="card-body">
                                    <p>Username: ${user.username}</p>
                                    <p>Email: ${user.email}</p>
                                    <p>Role: ${user.role.name}</p>
                                    <button class="btn btn-danger" data-id="${user.id}" onclick="deleteUser(${user.id})">Delete</button>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                    <div class="card">
                        <div class="card-body">
                            <h3>Create User</h3>
                            <div class="form-group">
                                <input id="newUsername" class="input" placeholder="Username" value="${state.newUser.username}">
                            </div>
                            <div class="form-group">
                                <input id="newEmail" class="input" placeholder="Email" value="${state.newUser.email}">
                            </div>
                            <div class="form-group">
                                <input id="newPassword" type="password" class="input" placeholder="Password" value="${state.newUser.password}">
                            </div>
                            <div class="form-group">
                                <input id="newRole" class="input" placeholder="Role" value="${state.newUser.role}">
                            </div>
                            <button id="createBtn" class="btn btn-success">Create</button>
                        </div>
                    </div>
                    <button id="logoutBtn" class="btn btn-danger">Logout</button>
                    <div id="webcli">
                        <h2>WebCLI</h2>
                        <input id="command" class="input" placeholder="Enter command (e.g., create_user john john123 john@example.com user)" value="${state.command}">
                        <div id="webcli-output">${state.output}</div>
                    </div>
                </div>
            `;
            bindAuthenticatedEvents();
        }
    }

    // Show flash message
    function showFlash(message, type) {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.innerHTML = message;
        document.body.appendChild(alert);
        setTimeout(() => alert.remove(), 3000);
    }

    // Bind events for login form
    function bindLoginEvents() {
        document.querySelector('#username').addEventListener('input', e => {
            state.username = e.target.value;
        });
        document.querySelector('#password').addEventListener('input', e => {
            state.password = e.target.value;
        });
        document.querySelector('#loginBtn').addEventListener('click', login);
    }

    // Bind events for authenticated view
    function bindAuthenticatedEvents() {
        document.querySelector('#newUsername').addEventListener('input', e => {
            state.newUser.username = e.target.value;
        });
        document.querySelector('#newEmail').addEventListener('input', e => {
            state.newUser.email = e.target.value;
        });
        document.querySelector('#newPassword').addEventListener('input', e => {
            state.newUser.password = e.target.value;
        });
        document.querySelector('#newRole').addEventListener('input', e => {
            state.newUser.role = e.target.value;
        });
        document.querySelector('#createBtn').addEventListener('click', createUser);
        document.querySelector('#logoutBtn').addEventListener('click', logout);
        document.querySelector('#command').addEventListener('keypress', e => {
            if (e.key === 'Enter') {
                state.command = e.target.value;
                runCommand();
            }
        });
    }

    // API calls
    async function login() {
        try {
            const response = await ar()
                .method('post')
                .url('/api/login')
                .csrfToken(state.csrfToken)
                .body({ username: state.username, password: state.password })
                .fetch();
            sessionStorage.setItem('token', response.token);
            state.loggedIn = true;
            state.username = '';
            state.password = '';
            await fetchUsers();
            showFlash('Login successful', 'success');
            render();
        } catch (e) {
            state.output = 'Login failed: ' + e.message;
            showFlash('Login failed', 'danger');
            render();
        }
    }

    async function fetchUsers() {
        try {
            const users = await ar()
                .url('/api/users')
                .header('Authorization', sessionStorage.getItem('token'))
                .fetch();
            state.users = users;
            render();
        } catch (e) {
            state.output = 'Failed to fetch users: ' + e.message;
            showFlash('Failed to fetch users', 'danger');
        }
    }

    async function createUser() {
        try {
            await ar()
                .method('post')
                .url('/api/users')
                .header('Authorization', sessionStorage.getItem('token'))
                .csrfToken(state.csrfToken)
                .body(state.newUser)
                .fetch();
            state.newUser = { username: '', email: '', password: '', role: 'user' };
            state.output = 'User created';
            showFlash('User created', 'success');
            await fetchUsers();
        } catch (e) {
            state.output = 'Failed to create user: ' + e.message;
            showFlash('Failed to create user', 'danger');
            render();
        }
    }

    window.deleteUser = async function(id) {
        try {
            await ar()
                .method('delete')
                .url(`/api/users/${id}`)
                .header('Authorization', sessionStorage.getItem('token'))
                .csrfToken(state.csrfToken)
                .fetch();
            state.output = 'User deleted';
            showFlash('User deleted', 'success');
            await fetchUsers();
        } catch (e) {
            state.output = 'Failed to delete user: ' + e.message;
            showFlash('Failed to delete user', 'danger');
        }
    };

    async function logout() {
        try {
            await ar()
                .method('post')
                .url('/api/logout')
                .header('Authorization', sessionStorage.getItem('token'))
                .csrfToken(state.csrfToken)
                .fetch();
            state.loggedIn = false;
            state.users = [];
            sessionStorage.removeItem('token');
            state.output = 'Logged out';
            showFlash('Logged out', 'success');
            render();
        } catch (e) {
            state.output = 'Logout failed: ' + e.message;
            showFlash('Logout failed', 'danger');
        }
    }

    async function runCommand() {
        try {
            const response = await ar()
                .method('post')
                .url('/api/webcli')
                .header('Authorization', sessionStorage.getItem('token'))
                .csrfToken(state.csrfToken)
                .body({ command: state.command })
                .fetch();
            state.output = JSON.stringify(response, null, 2);
            state.command = '';
            showFlash('Command executed', 'success');
            render();
        } catch (e) {
            state.output = 'Command failed: ' + e.message;
            showFlash('Command failed', 'danger');
            render();
        }
    }

    // Initialize
    if (sessionStorage.getItem('token')) {
        state.loggedIn = true;
        fetchUsers();
    }
    render();

    // EOF
})();