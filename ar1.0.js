const app = new Ar({
    el: '#app',
    template: `
        <div class="cx-container">
            <h1 cx-text="title">Test App Admin</h1>
            <div cx-show="!loggedIn" class="cx-card cx-m-md">
                <div class="cx-card-body cx-flex">
                    <div class="cx-form-group">
                        <input cx-bind="username" class="cx-input" placeholder="Username">
                    </div>
                    <div class="cx-form-group">
                        <input cx-bind="password" type="password" class="cx-input" placeholder="Password">
                    </div>
                    <button cx-on:click="login" class="cx-btn cx-btn-primary">Login</button>
                </div>
            </div>
            <div cx-show="loggedIn" class="cx-container">
                <h2 cx-text="usersTitle">Users</h2>
                <div class="cx-grid cx-md:grid-cols-3 cx-m-md">
                    <div class="cx-card cx-m-md" v-for="user in users">
                        <div class="cx-card-body">
                            <p cx-text="user.username">{{user.username}}</p>
                            <p cx-text="user.email">{{user.email}}</p>
                            <p cx-text="user.role.name">Role: {{user.role.name}}</p>
                            <button cx-on:click="deleteUser(user.id)" class="cx-btn cx-btn-danger cx-btn-sm">Delete</button>
                        </div>
                    </div>
                </div>
                <div class="cx-card cx-m-md">
                    <div class="cx-card-body cx-flex">
                        <h3>Create User</h3>
                        <div class="cx-form-group">
                            <input cx-bind="newUser.username" class="cx-input" placeholder="Username">
                        </div>
                        <div class="cx-form-group">
                            <input cx-bind="newUser.email" class="cx-input" placeholder="Email">
                        </div>
                        <div class="cx-form-group">
                            <input cx-bind="newUser.password" type="password" class="cx-input" placeholder="Password">
                        </div>
                        <div class="cx-form-group">
                            <input cx-bind="newUser.role" class="cx-input" placeholder="Role">
                        </div>
                        <button cx-on:click="createUser" class="cx-btn cx-btn-success">Create</button>
                    </div>
                </div>
                <button cx-on:click="logout" class="cx-btn cx-btn-danger cx-m-md">Logout</button>
                <div id="webcli" class="cx-m-md">
                    <h2>WebCLI</h2>
                    <input cx-bind="command" cx-on:keyup.enter="runCommand" class="cx-input" placeholder="Enter command (e.g., create_user john john123 john@example.com user)">
                    <div id="webcli-output" class="cx-text-sm">{{output}}</div>
                </div>
            </div>
        </div>
    `,
    data: {
        loggedIn: false,
        username: '',
        password: '',
        users: [],
        newUser: { username: '', email: '', password: '', role: 'user' },
        command: '',
        output: '',
        title: 'Test App Admin',
        usersTitle: 'Users'
    },
    methods: {
        async login() {
            try {
                const response = await Ar.client.ajax.post('/api/login', {
                    username: this.username,
                    password: this.password
                }, {
                    headers: { 'X-CSRF-Token': '<?php echo $config['app']['secret']; ?>' }
                });
                Ar.client.auth._token = response.token;
                this.loggedIn = true;
                this.fetchUsers();
                Ar.client.flash.show('Login successful', 'success');
            } catch (e) {
                this.output = 'Login failed: ' + e.message;
                Ar.client.flash.show('Login failed', 'danger');
            }
        },
        async fetchUsers() {
            try {
                const users = await Ar.client.ajax.get('/api/users', {
                    headers: { 'Authorization': Ar.client.auth._token }
                });
                this.users = users;
            } catch (e) {
                this.output = 'Failed to fetch users: ' + e.message;
            }
        },
        async createUser() {
            try {
                await Ar.client.ajax.post('/api/users', this.newUser, {
                    headers: { 
                        'Authorization': Ar.client.auth._token,
                        'X-CSRF-Token': '<?php echo $config['app']['secret']; ?>'
                    }
                });
                this.fetchUsers();
                this.newUser = { username: '', email: '', password: '', role: 'user' };
                this.output = 'User created';
                Ar.client.flash.show('User created', 'success');
            } catch (e) {
                this.output = 'Failed to create user: ' + e.message;
                Ar.client.flash.show('Failed to create user', 'danger');
            }
        },
        async deleteUser(id) {
            try {
                await Ar.client.ajax.delete(`/api/users/${id}`, {
                    headers: { 
                        'Authorization': Ar.client.auth._token,
                        'X-CSRF-Token': '<?php echo $config['app']['secret']; ?>'
                    }
                });
                this.fetchUsers();
                Ar.client.flash.show('User deleted', 'success');
            } catch (e) {
                this.output = 'Failed to delete user: ' + e.message;
                Ar.client.flash.show('Failed to delete user', 'danger');
            }
        },
        async logout() {
            try {
                await Ar.client.ajax.post('/api/logout', {}, {
                    headers: { 
                        'Authorization': Ar.client.auth._token,
                        'X-CSRF-Token': '<?php echo $config['app']['secret']; ?>'
                    }
                });
                this.loggedIn = false;
                this.users = [];
                Ar.client.auth.logout();
            } catch (e) {
                this.output = 'Logout failed: ' + e.message;
                Ar.client.flash.show('Logout failed', 'danger');
            }
        },
        async runCommand() {
            try {
                const response = await Ar.client.ajax.post('/api/webcli', { command: this.command }, {
                    headers: { 
                        'Authorization': Ar.client.auth._token,
                        'X-CSRF-Token': '<?php echo $config['app']['secret']; ?>'
                    }
                });
                this.output = JSON.stringify(response, null, 2);
                this.command = '';
                Ar.client.flash.show('Command executed', 'success');
            } catch (e) {
                this.output = 'Command failed: ' + e.message;
                Ar.client.flash.show('Command failed', 'danger');
            }
        }
    }
});