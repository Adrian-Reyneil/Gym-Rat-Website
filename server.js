require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const validator = require('validator');
const sgMail = require('@sendgrid/mail'); // Import SendGrid

const app = express();
const PORT = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URI;
sgMail.setApiKey(process.env.SENDGRID_API_KEY); // Set SendGrid API key

// Trust the proxy (if you're behind a load balancer or proxy)
app.set('trust proxy', 1);

// Session management with MongoDB store
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000 // 30 minutes
    }
}));

// Middleware configurations
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(helmet());

function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized access.' });
    }
}

// Protected route for the dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

// Helper functions
function hashPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
}

// Rate limiting for login route
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: function (req, res, next, options) {
        res.status(options.statusCode).json({ success: false, message: options.message });
    }
});

// MongoDB connection
mongoose.connect(mongoUri).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('MongoDB connection error:', error);
});

// Define Token Schema and Model
const userSchema = new mongoose.Schema({
    email: { type: String, required: true },
    password: { type: String, required: true },
    resetKey: String,
    resetExpires: Date,
    createdAt: { type: Date, default: Date.now },
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

const tokenSchema = new mongoose.Schema({
    email: { type: String, required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 },
}, { collection: 'tokens' });

const Token = mongoose.model('Token', tokenSchema);

// Generate random string for tokens
function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

// Generate 6-digit reset code
function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send Reset Code Email using SendGrid
async function sendResetCodeEmail(email, resetCode) {
    const msg = {
        from: 'edorianpuru@gmail.com',  // Ensure this is verified in SendGrid
        to: email,
        subject: 'Your Password Reset Code',
        text: `Your password reset code is: ${resetCode}`,
        html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
    };

    try {
        await sgMail.send(msg);
        console.log(`Reset code email sent to ${email}`);
    } catch (error) {
        console.error('Error sending reset code email:', error.response ? error.response.body : error.message);
        throw new Error('Error sending reset code email');
    }
}


app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send('Email is required');
    }

    try {
        // Check if the email exists in MongoDB
        let existingToken = await Token.findOne({ email: email });
        const resetToken = generateRandomString(32);

        if (existingToken) {
            // Update the token if the email exists
            existingToken.token = resetToken;
            await existingToken.save();
        } else {
            // Create a new token if the email doesn't exist
            const newToken = new Token({
                email: email,
                token: resetToken,
            });

            await newToken.save();
        }

        // Send the email with the token (You can call sendResetCodeEmail here if needed)
        res.status(200).json({ message: 'Password reset token generated and saved' });
    } catch (error) {
        console.error('Error processing forgot-password request:', error);
        res.status(500).json({ message: 'Error processing request' });
    }
});

// Send Password Reset
app.post('/send-password-reset', async (req, res) => {
    const { email } = req.body;

    try {
        // Find user by email
        const user = await User.findOne({ email: email }); // Changed 'emaildb' to 'email'
        if (!user) {
            return res.status(404).json({ message: 'No account with that email exists' });
        }

        const resetCode = generateCode(); // Generate a 6-digit reset code

        // Update the user's reset key and expiry time
        user.resetKey = resetCode;
        user.resetExpires = new Date(Date.now() + 3600000); // 1-hour expiry

        // Save the user with the updated fields
        await user.save();

        // Send the reset code via email
        await sendResetCodeEmail(email, resetCode);

        res.json({ message: 'Password reset code sent', redirectUrl: '/reset-password.html' });
    } catch (error) {
        console.error('Error processing request:', error);
        res.status(500).json({ message: 'Error processing request' });
    }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;

    try {
        // Find user by resetKey and check if it hasn't expired
        const user = await User.findOne({
            resetKey: resetKey,
            resetExpires: { $gt: new Date() } // Ensure resetExpires is in the future
        });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid or expired reset key.' });
        }

        // Hash the new password
        const hashedPassword = hashPassword(newPassword);
        user.password = hashedPassword;
        user.resetKey = null;
        user.resetExpires = null;

        await user.save();
        res.json({ success: true, message: 'Your password has been successfully reset.' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Error resetting password' });
    }
});
// Sign Up Route
// Sign Up Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        // Hash the password
        const hashedPassword = hashPassword(password);

        // Create and save the new user
        const newUser = new User({
            email,
            password: hashedPassword,
            // The createdAt field will be automatically set by the schema
        });

        // Save the user and log the saved user object
        const savedUser = await newUser.save();
        console.log('New User:', savedUser); // Log the newly created user

        res.json({ success: true, message: 'Account created successfully!' });
    } catch (error) {
        console.error('Error creating account:', error.stack || error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
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
        return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });

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

app.post('/logout', async (req, res) => {
        if (!req.session.userId) {
            return res.status(400).json({ success: false, message: 'No user is logged in.' });
        }
        try {
            req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ success: false, message: 'Logout failed.' });
        }
        res.clearCookie('connect.sid');
       });
        res.json({ success: true, message: 'Logged out successfully.' });
        } catch (error) {
            console.error('Error during logout:', error);
            res.status(500).json({ success: false, message: 'Logout failed.' });
        }
});
// Start the Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});