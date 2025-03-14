// app.js
require('dotenv').config(); // Load environment variables
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const flash = require('connect-flash');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

const app = express();

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/auth_demo')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(helmet()); // Security headers
app.use(express.urlencoded({ extended: true })); // Parse form data
app.use(express.json()); // Parse JSON data
app.use(express.static('public')); // Serve static files
app.use(cookieParser()); // Parse cookies

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key_here',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost/auth_demo' }),
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Secure cookies in production
    httpOnly: true // Prevent client-side JavaScript from accessing the cookie
  }
}));

// Flash messages
app.use(flash());

// CSRF protection
app.use(csrf({ cookie: true }));
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken(); // Make CSRF token available in views
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many attempts, please try again later.'
});
app.use('/login', authLimiter);
app.use('/signup', authLimiter);

// Set view engine (EJS)
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', [
  body('username')
    .trim()
    .equals('arnav').withMessage('Username must be "arnav"'),
  body('password')
    .trim()
    .equals('arnav').withMessage('Password must be "arnav"')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', errors.array()[0].msg);
    return res.redirect('/signup');
  }

  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 12);
    const user = new User({
      username: req.body.username,
      password: hashedPassword
    });

    await user.save();
    req.flash('success', 'Registration successful! Please login.');
    res.redirect('/login');
  } catch (error) {
    req.flash('error', 'User already exists');
    res.redirect('/signup');
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', [
  body('username')
    .trim()
    .equals('arnav').withMessage('Invalid credentials'),
  body('password')
    .trim()
    .equals('arnav').withMessage('Invalid credentials')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.flash('error', 'Invalid credentials');
    return res.redirect('/login');
  }

  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) {
      req.flash('error', 'User not found');
      return res.redirect('/login');
    }

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) {
      req.flash('error', 'Invalid credentials');
      return res.redirect('/login');
    }

    req.session.user = { username: user.username };
    res.redirect('/profile');
  } catch (error) {
    req.flash('error', 'Login failed');
    res.redirect('/login');
  }
});

app.get('/profile', (req, res) => {
  if (!req.session.user) {
    req.flash('error', 'Please login first');
    return res.redirect('/login');
  }
  res.render('profile', { user: req.session.user });
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});