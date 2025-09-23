const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = 'your_jwt_secret'; // Change this in production!
const USERS_FILE = path.join(__dirname, 'users.json');

// Load users from file or create default
let users = [];
try {
  if (fs.existsSync(USERS_FILE)) {
    users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } else {
    // Create default admin user
    users = [
      { 
        id: 1,
        username: 'admin', 
        email: 'admin@cookinghub.com',
        password: bcrypt.hashSync('admin123', 10), 
        role: 'admin',
        createdAt: new Date().toISOString()
      }
    ];
    saveUsers();
  }
} catch (error) {
  console.error('Error loading users:', error);
  users = [];
}

// Save users to file
function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Error saving users:', error);
  }
}

// Ensure favorites array exists for all users
users.forEach(u => { if (!u.favorites) u.favorites = []; });

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Role-based authorization middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Register endpoint
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || username.includes(' ') || !email || !password) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  const hashed = bcrypt.hashSync(password, 10);
  const user = { 
    id: users.length > 0 ? Math.max(...users.map(u => u.id || 0)) + 1 : 1,
    username, 
    email, 
    password: hashed, 
    role: 'user',
    createdAt: new Date().toISOString()
  };
  users.push(user);
  saveUsers(); // Save to file
  const token = jwt.sign({ id: user.id, email, role: user.role }, SECRET, { expiresIn: '1d' });
  res.json({ user: { id: user.id, username, email, role: user.role }, token, role: user.role });
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ email, role: user.role }, SECRET, { expiresIn: '1d' });
  res.json({ user: { username: user.username, email, role: user.role }, token, role: user.role });
});

// Protected route example
app.get('/api/profile', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], SECRET);
    res.json({ user: decoded });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// GET /api/favorites - get current user's favorite recipe IDs
app.get('/api/favorites', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ favorites: user.favorites });
});

// POST /api/favorites/:id - add a recipe ID to favorites
app.post('/api/favorites/:id', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const recipeId = req.params.id;
  if (!user.favorites.includes(recipeId)) {
    user.favorites.push(recipeId);
    saveUsers();
  }
  res.json({ favorites: user.favorites });
});

// DELETE /api/favorites/:id - remove a recipe ID from favorites
app.delete('/api/favorites/:id', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const recipeId = req.params.id;
  user.favorites = user.favorites.filter(id => id !== recipeId);
  saveUsers();
  res.json({ favorites: user.favorites });
});

app.get('/api/dashboard', authenticateToken, (req, res) => {
  const user = users.find(u => u.email === req.user.email);
  res.json({ 
    message: `Welcome to your dashboard, ${user.username}!`,
    user: { 
      id: user.id, 
      username: user.username, 
      email: user.email, 
      role: user.role,
      createdAt: user.createdAt 
    },
    stats: {
      totalRecipes: 3,
      favoriteRecipes: 1,
      lastLogin: new Date().toISOString()
    }
  });
});

// Admin-only route
app.get('/api/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
  const safeUsers = users.map(({ password, ...user }) => user);
  res.json({ users: safeUsers });
});

// Token validation endpoint
app.get('/api/validate-token', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

app.listen(3001, () => console.log('Backend running on http://localhost:3001'));