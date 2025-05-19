const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const authMiddleware = require('./middleware/auth');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = 'abcdfefhg';

// Helper functions to read/write JSON files safely
function readJSON(filename) {
  if (!fs.existsSync(filename)) {
    fs.writeFileSync(filename, JSON.stringify([]));
  }
  const data = fs.readFileSync(filename, 'utf8');
  return JSON.parse(data);
}

function writeJSON(filename, data) {
  fs.writeFileSync(filename, JSON.stringify(data, null, 2));
}

// Register
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Username and password required' });

  const users = readJSON('users.json');

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = bcrypt.hashSync(password, 8);
  users.push({ username, password: hashedPassword });
  writeJSON('users.json', users);
  res.json({ message: 'User registered successfully' });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Username and password required' });

  const users = readJSON('users.json');
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Save data
app.post('/save', authMiddleware, (req, res) => {
  // Read existing data object
  let data = {};
  if (fs.existsSync('data.json')) {
    data = JSON.parse(fs.readFileSync('data.json', 'utf8'));
  }
  // Save data for the logged in user
  data[req.user.username] = req.body.data; // assume frontend sends { data: {...} }
  writeJSON('data.json', data);

  res.json({ message: 'Data saved successfully' });
});

// Read data
app.get('/read', authMiddleware, (req, res) => {
  let data = {};
  if (fs.existsSync('data.json')) {
    data = JSON.parse(fs.readFileSync('data.json', 'utf8'));
  }
  const userData = data[req.user.username] || {};
  res.json({ data: userData });
});

// Start server
app.listen(5000, () => console.log('Server running on port 5000'));
