require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(helmet());
app.use(cors());
app.set('trust proxy', 1);

// MongoDB URI and Session Secret Validation
const mongoUri = process.env.MONGODB_URI;
const sessionSecret = process.env.SESSION_SECRET;
if (!mongoUri || !sessionSecret) {
    console.error('Required environment variables (MONGODB_URI or SESSION_SECRET) are missing.');
    process.exit(1);
}

const client = new MongoClient(mongoUri);
let usersCollection;

async function connectToDatabase() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const database = client.db('test'); // Replace with your database name
        usersCollection = database.collection('users');
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}

connectToDatabase();

// Cleanup Database Connection on Exit
process.on('SIGINT', async () => {
    await client.close();
    console.log('Database connection closed.');
    process.exit(0);
});

// Session Management with Expiration on Server Restart
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri, ttl: 30 * 60 }),
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // 30 minutes
    }
}));

// MongoDB client for session storage
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => {
        console.log("MongoDB connected successfully.");
    })
    .catch((err) => {
        console.error("MongoDB connection error:", err);
    });

// SendGrid API Key Setup
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// User Schema
const userSchema = new mongoose.Schema({
    emaildb: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetKey: { type: String },
    resetExpires: { type: Date },
});
const User = mongoose.model('User', userSchema);

// Token Schema
const tokenSchema = new mongoose.Schema({
    email: { type: String, required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 },
});
const Token = mongoose.model('Token', tokenSchema);

// Helper Functions
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

async function sendResetCodeEmail(email, resetCode) {
    const msg = {
        to: email,
        from: 'adrianlacbao.10@gmail.com', // Replace with your verified SendGrid email
        subject: 'Your Password Reset Code',
        text: `Your password reset code is: ${resetCode}`,
        html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
    };
    await sgMail.send(msg);
}

// Rate Limiting for Login Route
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again after 30 minutes.'
});

function isValidPassword(password) {
    // Define password criteria, e.g., at least 8 characters, one uppercase letter, and one number
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    return passwordRegex.test(password);
  }

// Login Route Implementation
app.post('/index', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
        if (!validator.isEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email format.' });

        const user = await usersCollection.findOne({ emaildb: email });
        if (!user) return res.status(400).json({ success: false, message: 'Invalid email or password.' });

        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
            return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes. `});
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
            let updateFields = { invalidLoginAttempts: invalidAttempts };

            if (invalidAttempts >= 3) {
                updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
                updateFields.invalidLoginAttempts = 0;
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
            } else {
                await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
                return res.status(400).json({ success: false, message: 'Invalid email or password.' });
            }
        }

        await usersCollection.updateOne(
            { _id: user._id },
            { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
        );

        req.session.userId = user._id;
        req.session.email = user.emaildb;
        req.session.role = user.role;
        req.session.studentIDNumber = user.studentIDNumber;

        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.json({ success: true, role: user.role, message: 'Login successful!' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login.' });
    }
});

// Sign Up Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
        if (!isValidPassword(password)) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.' });
        }

        const existingUser = await usersCollection.findOne({ emaildb: email });
        if (existingUser) return res.status(400).json({ success: false, message: 'Email already registered.' });

        const hashedPassword = hashPassword(password);
        await usersCollection.insertOne({ emaildb: email, password: hashedPassword });
        
        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// Route to fetch user details (email) if authenticated
app.get('/user-details', isAuthenticated, (req, res) => {
    try {
        // Send user details as a response
        res.json({ success: true, user: { email: req.session.email } });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'Error fetching user details.' });
    }
});

// Middleware for Authentication
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
}

// Protected Routes
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json('Email is required');
    }

    try {
        let existingToken = await Token.findOne({ email });
        const resetToken = generateRandomString(32);

        if (existingToken) {
            existingToken.token = resetToken;
            await existingToken.save();
        } else {
            const newToken = new Token({ email, token: resetToken });
            await newToken.save();
        }

        res.status(200).json({ message: 'Password reset token generated and saved' });
    } catch (error) {
        console.error('Error processing forgot-password request:', error);
        res.status(500).json({ message: 'Error processing request' });
    }
});

// Send Password Reset Route
app.post('/send-password-reset', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ emaildb: email });
        if (!user) {
            return res.status(404).json({ message: 'No account with that email exists' });
        }

        const resetCode = generateRandomString(6);
        user.resetKey = resetCode;
        user.resetExpires = new Date(Date.now() + 3600000); // 1-hour expiry
        await user.save();

        await sendResetCodeEmail(email, resetCode);
        res.json({ message: 'Password reset code sent', redirectUrl: '/reset-password.html' });
    } catch (error) {
        console.error('Error processing request:', error);
        res.status(500).json({ message: 'Error processing request' });
    }
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;
    try {
        // Find the user by reset key and check if the reset key is valid (not expired)
        const user = await User.findOne({
            resetKey,
            resetExpires: { $gt: new Date() } // Ensure reset key is still valid (not expired)
        });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
        }

        // Hash the new password
        const hashedPassword = await hashPassword(newPassword);

        // Update the user's password and clear the reset fields
        user.password = hashedPassword;
        user.resetKey = null; // Clear the reset key
        user.resetExpires = null; // Clear the reset expiration
        await user.save();

        res.json({ success: true, message: 'Your password has been successfully reset.' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Error resetting password' });
    }
});
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    try {
      // Input validation
      if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
      }
      if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
      }
  
      // Fetch user from the database
      const user = await User.findOne({ email: email });
      if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid email or password.' });
      }
  
      // Check for account lockout
      if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
        const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
        return res.status(403).json(`{ success: false, message: Account is locked. Try again in ${remainingTime} minutes. }`);
      }
  
      // Password verification
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        // Handle failed attempts
        let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
        let updateFields = { invalidLoginAttempts: invalidAttempts };
  
        // Lock the account if attempts exceed threshold
        if (invalidAttempts >= 3) {
          updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes lock
          updateFields.invalidLoginAttempts = 0;
          await User.updateOne({ _id: user._id }, { $set: updateFields });
          return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
        } else {
          // Update failed attempts
          await User.updateOne({ _id: user._id }, { $set: updateFields });
          return res.status(400).json({ success: false, message: 'Invalid email or password.' });
        }
      }
  
      // Successful login
      await User.updateOne(
        { _id: user._id },
        { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
      );
  
      // Save session details
      req.session.userId = user._id;
      req.session.email = user.email;
      req.session.role = user.role;
      req.session.studentIDNumber = user.studentIDNumber;
  
      // Ensure session is saved before responding
 await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        res.json({ success: true, message: 'Login successful!', redirectUrl: '/dashboard.html' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'Error during login.' });
    }
});
app.get('/user-details', isAuthenticated, async (req, res) => {
    try {
        const email = req.session.email;
        if (!email) {
            return res.status(401).json({ success: false, message: 'Unauthorized access.' });
        }
        // Fetch user details from the database
        const user = await User.findOne({ email: email }, 'email');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.json({
            success: true,
            user: { email: user.email }
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'Error fetching user details.' });
    }
});

// Logout Route
app.post('/logout', async (req, res) => {
    try {
        req.session.destroy((err) => {
            if (err) {
                console.error('Error during logout:', err);
                return res.status(500).json({ success: false, message: 'Error during logout.' });
            }
            res.clearCookie('connect.sid');
            res.json({ success: true, message: 'Logged out successfully.' });
        });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ success: false, message: 'Error during logout.' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
});